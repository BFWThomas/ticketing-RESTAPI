const express = require('express');
const bodyParser = require('body-parser');
const { Datastore } = require('@google-cloud/datastore');

const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const { auth } = require('express-openid-connect');

// Setup
const app = express();
const datastore  = new Datastore();

const users = express.Router();
const tickets = express.Router();
const events = express.Router();
const venues = express.Router();

app.use(bodyParser.json());

const OFFSET = 5;

const CLIENT_ID = '';
const CLIENT_SECRET = '';
const DOMAIN = '';
const PROTO = 'https'
const HOST = '';

// auth0 setup
const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256']
});

const config = {
    authRequired: false,
    auth0Logout: true,
    baseURL: `${PROTO}://${HOST}`,
    clientID: CLIENT_ID,
    issuerBaseURL: `https://${DOMAIN}`,
    secret: CLIENT_SECRET
}

app.use(auth(config));

/* ------ Helper functions ------ */

async function getUserByEmail(email) {
    const query = datastore
        .createQuery('user')
        .filter('email', '=', email)
        .limit(1);

    const [users] = await datastore.runQuery(query);
    return users[0];
}

async function getTicketByID(id) {
    const ticket = await datastore.get(datastore.key(['ticket', parseInt(id, 10)]));
    return ticket;
}

async function getEventByID(id) {
    const event = await datastore.get(datastore.key(['event', parseInt(id, 10)]));
    return event;
}

async function getVenueByID(id) {
    const venue = await datastore.get(datastore.key(['venue', parseInt(id, 10)]));
    return venue;
}

async function venueHasName(name) {
    const query = datastore
    .createQuery('venue')
    .filter('name', '=', name);

    const [venues] = await datastore.runQuery(query);
    if (!venues) {
        venues = [];
    }
    return venues;
}


/* ------ Request Calls ------ */

/*
    ---User---
    id              String  req
    name            String  req
    email         String  req
    tickets         Array
*/

// Read user information
app.get('/users', async (req, res, next) => {
    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }
    if (!req.headers.authorization) {
        // Get all users
        try {
            // Get paginated users
            const page = req.query.page ? parseInt(req.query.page, 10) : 0;
            
            const query = datastore
            .createQuery('user')
            .limit(OFFSET)
            .offset(OFFSET * page);
            
            let [users] = await datastore.runQuery(query);

            // Construct response and send
            users = users.map((user => {
                return {
                    "id": user[datastore.KEY].id,
                    "self": req.protocol + "://" + req.get("host") + "/users/" + user[datastore.KEY].id
                }
            }));

            // Get the Users count
            const countQuery = datastore
            .createQuery('user')
            .select('__key__');

            const [total] = await datastore.runQuery(countQuery);

            let response = { 
                "users": users.slice(0, 5),
                "totalCount": total.length
            };

            if (users.length > OFFSET) {
                response.next = req.protocol + "://" + req.get("host") + "/users?page=" + (page + 1);
            }

            res.status(200).json(response);
        } catch (err) {
            console.error('Error:', err);
            res.status(500).json({"Error": "Internal Server Error"});
        }
    } else {
        next();
    }
}, checkJwt, async (req, res) => {
    // Get current user
    const user = await getUserByEmail(req.auth.email);

    if (user) {
        let phone = null;
        if (user.phone) {
            phone = user.phone;
        }
        res.status(200).json({
            "id": user[datastore.KEY].id,
            "name": user.name,
            "email": user.email,
            "phone": phone,
            "tickets": user.tickets,
            "self": req.protocol + "://" + req.get("host") + "/users/" + user[datastore.KEY].id
        });
    } else {
        res.status(404).json({
            "Error": "User not found"
        });
    }
});

// Get all tickets for authenticated user
// DEPRECIATED
app.get('/users/tickets', (req, res) => {
    res.status(405).json({
        "Error": "Use GET /tickets resource"
    });
});

// Update user
app.patch('/users', (req, res, next) => {
    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    if (!req.headers.authorization) {
        res.status(401).json({
            "Error": "Unauthorized Access"
        });
    } else {
        next();
    }
}, checkJwt, async (req, res) => {
    const { name, phone, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    // Validate request
    if (Object.keys(other).length > 0) {
        return res.status(400).json({
            "Error": "Invalid attribute"
        });
    }

    if (phone && !/^\d{10}$/.test(phone)) {
        return res.status(400).json({
            "Error": "Phone must be 10 numerical digits"
        })
    }

    // Validate user
    const user = await getUserByEmail(req.auth.email);
    if (user) {
        // Update user
        const key = datastore.key(['user', parseInt(user[datastore.KEY].id)]);
        user.name = name;
        await datastore.save(user);

        res.status(200).json({
            "id": user[datastore.KEY].id,
            "name": name || user.name,
            "email": user.email,
            "phone": phone || user.phone,
            "self": req.protocol + "://" + req.get("host") + "/users/" + user[datastore.KEY].id
        })
    } else {
        res.status(404).json(
            {"Error": "User not found"
        });
    }
});

// Delete user
app.delete('/users', (req, res, next) => {
    if (!req.headers.authorization) {
        res.status(401).json({
            "Error": "Unauthorized Access"
        });
    } else {
        next();
    }
}, checkJwt, async (req, res) => {
    const user = await getUserByEmail(req.auth.email);

    if (!user) {
        res.status(404).json({
            "Error": "User not found"
        });
    } else if (user.email != req.auth.email) {
        res.status(403).json({
            "Error": "Unauthorized to delete this account"
        });
    } else {
        // Remove user from tickets
        for (let i = 0; i < user.tickets.length; i++) {
            const ticket = getTicketByID(user.tickets[i]);

            ticket.user = null;
            await datastore.save(ticket);
        }

        // Delete User
        await datastore.delete(user.key);
        res.status(204).end();
    }
});

// Assign ticket to user
app.put('/users/tickets/:ticket_id', (req, res, next) => {
    if (!req.headers.authorization) {
        res.status(401).json({"Error": "Unauthorized Access"});
    } else {
        next();
    }  
}, checkJwt, async (req, res) => {
    const ticket_id = req.params.ticket_id;
    const user = await getUserByEmail(req.auth.email);
    const ticket = await getTicketByID(ticket_id);
    

    if (!user) {
        return res.status(404).json({"Error": "User not found"});
    }
    if (!ticket[0]) {
        return res.status(404).json({"Error": "Ticket not found"});
    }

    // Ticket already purchased by someone else
    if (ticket[0].user != null) {
        return res.status(403).json({"Error": "Ticket already belongs to another user"});
    }

    // Create relationship between ticket and user
    ticket[0].user = user[datastore.KEY].id;
    user.tickets.push(ticket_id);
    await datastore.save(ticket);
    await datastore.save(user);

    res.status(204).end();
});

// Remove ticket from user
app.delete('/users/tickets/:ticket_id', (req, res, next) => {
    if (!req.headers.authorization) {
        res.status(401).json({"Error": "Unauthorized Access"});
    } else {
        next();
    }  
}, checkJwt, async (req, res) => {
    const ticket_id = req.params.ticket_id;
    const user = await getUserByEmail(req.auth.email);
    const ticketArray = await getTicketByID(ticket_id);
    const ticket = ticketArray[0];

    if (!user) {
       return res.status(404).json({"Error": "User not found"});
    }
    if (!ticket) {
        return res.status(404).json({"Error": "Ticket not found"});
    }

    // Ticket does not belong to user
    if (ticket.user != user[Datastore.KEY].id) {
        return res.status(403).json({"Error": "Forbidden, Ticket does not belong to this User"});
    }

    // Remove relationship between ticket and user
    ticket.user = null;

    const index = user.tickets.indexOf(ticket_id);
    if (index > -1) {
        user.tickets.splice(index, 1);
    } else {
        // Ticket not associated with user
        return res.status(404).json({"Error": "Ticket not found in User"})
    }
    await datastore.save(ticket);
    await datastore.save(user);

    res.status(204).end();
});

/*
    ---Ticket---
    id              String  req
    user            String
    event           String  req
    type            Date    req
    cost            float   req
    seat            String
*/
// Create tickets
app.post('/tickets', async (req, res) => {
    const { event, type, cost, seat, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Validate request
    if (Object.keys(other).length > 0) {
        return res.status(400).json({
            "Error": "Invalid attribute"
        });
    }

    if (!event || !type || (cost === null || cost === undefined)) {
        return res.status(400).json({
            "Error": "Missing attribute from request"
        });
    }

    if (type === 'Seated' && !seat) {
        return res.status(400).json({
            "Error": "Seat number must be set if ticket type is Seated"
        });
    }

    if (cost < 0) {
        return res.status(400).json({
            "Error": "Invalid attribute value"
        });
    }

    // Event exists
    const key = datastore.key(['event', parseInt(event, 10)]);
    const [eventEntity] = await datastore.get(key);
    if (!eventEntity) {
        return res.status(400).json({
            "Error": "Invalid Event ID provided"
        });
    }
    
    // Validated, store event
    const ticket = {
        key: datastore.key('ticket'),
        data: {
            "user": null,
            "event": event,
            "type": type,
            "cost": cost.toFixed(2),
            "seat": seat,
        }
    }

    // Save the new event
    await datastore.save(ticket);

    // Add ticket to event
    eventEntity.tickets.push(ticket.key.id);
    datastore.save(eventEntity);

    // Response
    res.status(201).json({
        "id": ticket.key.id,
        "user": null,
        "event": event,
        "type": type,
        "cost": cost,
        "seat": seat,
        "self": req.protocol + "://" + req.get("host") + "/tickets/" + ticket.key.id
    });
});

// Read all tickets
// Without JWT show all unowned
// WIth, show tickets related to user
app.get('/tickets', async (req, res, next) => {
    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    if (!req.headers.authorization) {
        const page = req.query.page ? parseInt(req.query.page, 10) : 0;
        const query = datastore
            .createQuery('ticket')
            .filter('user', '=', null)
            .limit(OFFSET + 1)
            .offset(OFFSET * page);

        try {
            let [tickets] = await datastore.runQuery(query);

            // Construct response and send
            tickets = tickets.map((ticket => {
                return {
                    "id": ticket[datastore.KEY].id,
                    ...ticket,
                    "self": req.protocol + "://" + req.get("host") + "/tickets/" + ticket[datastore.KEY].id
                }
            }));

            // Get the Tickets count
            const countQuery = datastore
                .createQuery('ticket')
                .select('__key__');

            const [total] = await datastore.runQuery(countQuery);
            
            let response = {
                "tickets": tickets.slice(0, 5),
                "totalCount": total.length
            };
            
            if (tickets.length > OFFSET) {
                response.next = req.protocol + "://" + req.get("host") + "/tickets?page=" + (page + 1);
            }
            res.status(200).json(response);
        } catch (err) {
            console.error('Error:', err);
            res.status(500).json({"Error": "Internal Server Error"});
        }
    } else {
        next();
    }
}, checkJwt, async (req, res) => {
    const user = await getUserByEmail(req.auth.email);

    if (user) {
        const page = req.query.page ? parseInt(req.query.page, 10) : 0;

        const countQuery = datastore
            .createQuery('ticket')
            .select('__key__');

        const [total] = await datastore.runQuery(countQuery);


        let response = { 
            "tickets": user.tickets
                .slice((OFFSET * page), (OFFSET * page + OFFSET))
                .map((ticket) => ({
                    id: ticket,
                    self: req.protocol + "://" + req.get("host") + "/tickets/" + ticket
                })),
            "totalCount": total.length
        };
        if (user.tickets.length > OFFSET * page + OFFSET) {
            response.next = req.protocol + "://" + req.get("host") + "/tickets?page=" + (page + 1)
        }
        res.status(200).json(response);
    } else {
        res.status(404).json({"Error": "User not found"});
    }
});

// Read single tickets
app.get('/tickets/:id', async (req, res) => {
    const id = req.params.id;
    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }
    
    try {
        const ticket = await getTicketByID(id);

        if (!ticket) {
            return res.status(404).json({"Error": "Ticket not found"});
        }

        ticket.self = req.protocol + "://" + req.get("host") + "/tickets/" + id;
    
        res.status(200).json(ticket);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Update tickets
app.patch('/tickets/:id', async (req, res) => {
    const id = req.params.id;
    const { event, type, cost, seat, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Validate
    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    try {
        const ticketArray = await getTicketByID(id);
        const ticket = ticketArray[0];
        if (!ticket) {
            return res.status(404).json({"Error": "Ticket not found"});
        }

        if (event) {
            // Make sure event exists
            const foundEvent = await getEventByID(event);
            if (!foundEvent) {
                return res.status(404).json({"Error": "Event not found"});
            }

            if (ticket.event) {
                const oldEvent = await getEventByID(ticket.event)
                // Remove Ticket from old Event
                for (let i = 0; i < oldEvent.tickets.length; i++) {
                    if (oldEvent.tickets[i] === ticket.event) {
                        oldEvent.tickets.splice(i, 1);
                        await datastore.save(oldEvent);
                        break;
                    }
                }
            }
        }

        // Make sure seat not already assigned to ticket
        if (seat) {
            const foundEvent = await getEventByID(event);
            if (!foundEvent) {
                return res.status(404).json({"Error": "Event not found"});
            }

            // Check other tickets
            for (let i = 0; i < foundEvent.tickets.length; i++) {
                if (foundEvent.tickets[i].seat === seat) {
                    return res.status(400).json({"Error": "Seat already assigned to ticket"});
                }
            }
        }

        const key = datastore.key(['ticket', parseInt(id, 10)]);
        const data = {
            "user": ticket.user,
            "event": event || ticket.event,
            "type": type || ticket.type,
            "cost": cost || ticket.cost,
            "seat": seat || ticket.seat,
        }

        await datastore.update({
            key: key,
            data: data
        });

        data.id = id;
        data.self = req.protocol + "://" + req.get("host") + "/tickets/" + id;
        res.status(200).json(data);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

app.put('/tickets/:id', async (req, res) => {
    const id = req.params.id;
    const { event, type, cost, seat, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Validate
    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    if (!event || !type || !cost || seat === undefined) {
        return res.status(400).json({
            "Error": "Missing required attribute"
        });
    }

    try {
        const ticket = await getTicketByID(id);
        if (!ticket) {
            return res.status(404).json({"Error": "Ticket not found"});
        }

        // Make sure event exists
        const foundEvent = await getEventByID(event);
        if (!foundEvent) {
            return res.status(404).json({"Error": "Event not found"});
        }

        // Remove Ticket from old Event
        for (let i = 0; i < foundEvent.tickets.length; i++) {
            if (foundEvent.tickets[i] === ticket.event) {
                foundEvent.tickets.splice(i, 1);
                await datastore.save(foundEvent);
                break;
            }
        }

        // Make sure seat not already assigned to ticket
        if (!foundEvent) {
            return res.status(404).json({"Error": "Event not found"});
        }

        // Check other tickets
        for (let i = 0; i < foundEvent.tickets.length; i++) {
            if (foundEvent.tickets[i].seat === seat) {
                return res.status(400).json({"Error": "Seat already assigned to ticket"});
            }
        }

        const key = datastore.key(['event', parseInt(id, 10)]);
        const data = {
            "user": ticket.user,
            "event": event,
            "type": type,
            "cost": cost,
            "seat": seat
        }

        await datastore.update({
            key: key,
            data: data
        })

        data.id = id;
        data.self = req.protocol + "://" + req.get("host") + "/tickets/" + ticket.id;
        res.status(200).json(data);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Delete tickets
app.delete('/tickets/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const key = datastore.key(['ticket', parseInt(id, 10)]);
        const [ticket] = await datastore.get(key);

        if (!ticket) {
            return res.status(404).json({"Error": "Ticket not found"});
        }

        if (ticket.user != null) {
            const [user] = datastore.get(datastore.key(['user', parseInt(ticket.user, 10)]));
            for (let i = 0; i < user.tickets.length; i++) {
                if (user.tickets[i] === id) {
                    user.tickets.splice(i, 1);
                    break;
                }
            }
        }

        if (ticket.event) {
            const [event] = await datastore.get(datastore.key(['event', parseInt(ticket.event, 10)]));
            for (let i = 0; i < event.tickets.length; i++) {
                if (event.tickets[i] === ticket.event) {
                    event.tickets.splice(i, 1);
                    await datastore.save(event);
                    break;
                }
            }
        }

        await datastore.delete(key);
        res.status(204).end();
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

/*
    ---Event---
    id              String  req
    name            String  req
    venue           String  req
    date            Date    req
    tickets         Array
    restrictions    Array
*/
// Create event
app.post('/events', async (req, res) => {
    const { name, venue, date, restrictions, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Validate request
    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    const restrictionsVal = restrictions || [];
    if (!name || !venue || !date) {
        return res.status(400).json({"Error": "Missing attribute from request"});
    }

    const key = datastore.key(['venue', parseInt(venue, 10)]);
    const [venueEntity] = await datastore.get(key);

    if (!venueEntity) {
        return res.status(400).json({"Error": "Invalid Venue ID provided"});
    }

    // Check date
    for (let i = 0; i < venueEntity.events.length; i++) {
        const event = getEventByID(venueEntity.events[i]);

        if (event.date === date) {
            return res.status(400).json({"Error": "Venue already booked on this date"});
        }
    }
    
    // Validated, store event
    const event = {
        key: datastore.key('event'),
        data: {
            "name": name,
            "venue": venue,
            "date": date,
            "tickets": [],
            "restrictions": restrictionsVal
        }
    }

    // Save the new event
    await datastore.save(event);
    res.status(201).json({
        "id": event.key.id,
        "name": name,
        "venue": venue,
        "date": date,
        "tickets": [],
        "restrictions": restrictionsVal,
        "self": req.protocol + "://" + req.get("host") + "/events/" + event.key.id
    });
});

// Read all event
app.get('/events', async (req, res) => {
    const page = req.query.page ? parseInt(req.query.page, 10) : 0;

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    const query = datastore
        .createQuery('event')
        .limit(OFFSET+1)
        .offset(OFFSET * page);

    try {
        // Get events
        let [events] = await datastore.runQuery(query);

        // Construct response and send
        events = events.map((event => {
            return {
                "id": event[datastore.KEY].id,
                ...event,
                "self": req.protocol + "://" + req.get("host") + "/events/" + event[datastore.KEY].id
            }
        }));

        // Get Events count
        const countQuery = datastore
            .createQuery('event')
            .select('__key__');

        const [total] = await datastore.runQuery(countQuery); 

        let response = {
            "events": events.slice(0, 5),
            "totalCount": total.length
        };
        if (events.length > OFFSET) {
            response.next = req.protocol + "://" + req.get("host") + "/events?page=" + (page + 1);
        }
        res.status(200).json(response);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Read single event
app.get('/events/:id', async (req, res) => {
    const id = req.params.id;

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    try {
        const event = await getEventByID(id);

        if (!event) {
            return res.status(404).json({"Error": "Event not found"});
        }
    
        event.self = req.protocol + "://" + req.get("host") + "/events/" + id;
        res.status(200).json(event);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Read event's tickets
app.get('/events/:id/tickets', async (req, res) => {
    const id = req.params.id;

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    try {
        const event = await getEventByID(id);

        if (!event) {
            return res.status(404).json({"Error": "Event not found"});
        }

        let tickets = [];

        for (let i = 0; i < event.tickets.length; i++) {
            let ticket = getTicketByID(event.tickets[i]);
            let ticketInfo = {
                "id" : event.tickets[i],
                "user": ticket.user,
                "type": ticket.type,
                "cost": ticket.cost,
                "seat": ticket.seat,
                "self": req.protocol + "://" + req.get("host") + "/tickets/" + event.ticket[i]
            }
            tickets.push(ticketInfo);
        }

        res.status(200).json(tickets);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Update event
app.patch('/events/:id', async (req, res) => {
    const id = req.params.id;
    let { name, venue, date, restrictions, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Validate
    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    try {
        const eventArray = await getEventByID(id);
        const event = eventArray[0];
        if (!event) {
            return res.status(404).json({"Error": "Event not found"});
        }

        if (venue) {
            const foundVenue = await getVenueByID(venue);
            if (!foundVenue) {
                return res.status(404).json({"Error": "Venue not found"});
            }
    
            // Check date
            for (let i = 0; i < foundVenue.events.length; i++) {
                const event = getEventByID(foundVenue.events[i]);

                if (event.date === date) {
                    return res.status(400).json({"Error": "Venue already booked on this date"});
                }
            }

            // Remove Event from old Venue
            for (let i = 0; i < foundVenue.events.length; i++) {
                if (foundVenue.events[i] === event.venue) {
                    foundVenue.events.splice(i, 1);
                    await datastore.save(foundVenue);
                    break;
                }
            }
        }
        
        if (name === undefined) {
            name = event.name;
        }
        if (venue === undefined) {
            venue = event.venue;
        }
        if (date === undefined) {
            date = event.date;
        }
        if (restrictions === undefined) {
            restrictions = event.restrictions;
        }

        const key = datastore.key(['event', parseInt(id, 10)]);
        const data = {
            "name": name,
            "venue": venue,
            "date": date,
            "tickets": event.tickets,
            "restrictions": restrictions
        }

        await datastore.update({
            key: key,
            data: data
        })

        data.id = id;
        data.self = req.protocol + "://" + req.get("host") + "/events/" + id;
        res.status(200).json(data);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Update event
app.put('/events/:id', async (req, res) => {
    const id = req.params.id;
    const { name, venue, date, restrictions, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Validate
    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    if (!name || !venue || !date || !restrictions) {
        return res.status(400).json({
            "Error": "Missing required attribute"
        });
    }

    try {
        const event = await getEventByID(id);
        if (!event) {
            return res.status(404).json({"Error": "Event not found"});
        }

        const foundVenue = await getVenueByID(venue);
        if (!foundVenue) {
            return res.status(404).json({"Error": "Venue not found"});
        }

        // Check date
        for (let i = 0; i < foundVenue.events.length; i++) {
            const checkevent = getEventByID(foundVenue.events[i]);

            if (checkevent.date === date) {
                return res.status(400).json({"Error": "Venue already booked on this date"});
            }
        }

            // Remove Event from old Venue
            for (let i = 0; i < foundVenue.events.length; i++) {
                if (foundVenue.events[i] === event.venue) {
                    foundVenue.events.splice(i, 1);
                    await datastore.save(foundVenue);
                    break;
                }
            }

        const key = datastore.key(['event', parseInt(id, 10)]);
        const data = {
            "name": name,
            "venue": venue,
            "date": date,
            "tickets": event.tickets,
            "restrictions": restrictions
        }

        await datastore.update({
            key: key,
            data: data
        })

        data.self = req.protocol + "://" + req.get("host") + "/events/" + id;
        res.status(200).json(data);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Delete event
app.delete('/events/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const key = datastore.key(['event', parseInt(id, 10)]);
        const [event] = await datastore.get(key);

        if (!event) {
            return res.status(404).json({"Error": "Venue not found"});
        }

        const [venue] = await datastore.get(datastore.key(['venue', parseInt(event.venue, 10)]));

        for (let i = 0; i < venue.events.length; i++) {
            if (venue.events[i] === event.venue) {
                venue.events.splice(i, 1);
                await datastore.save(venue);
                break;
            }
        }

        await datastore.delete(key);
        res.status(204).end();
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

/*
    ---Venue---
    id              String  req
    name            String  req
    address         String  req
    type            String  req
    events          Array
    restrictions    Array
*/
// Create venue
app.post('/venues', async (req, res) => {
    let { name, address, type, restrictions, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType != 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Validate request
    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    if (!restrictions) {
        restrictions = [];
    }

    if (!name || !address || !type) {
        return res.status(400).json({"Error": "Missing attribute from request"});
    }
    
    // Enforce unique name/address combination
    const venues = Object.values(await venueHasName(name));
    
    if (venues.length > 0) {
        for (let i = 0; i < venues.length; i++) {
            if (venues[i].address === address) {
                return res.status(400).json({"Error": "Venue with this name already exists at this address"});
            }
        }
    }

    // Validated, store venue
    const venue = {
        key: datastore.key('venue'),
        data: {
            "name": name,
            "address": address,
            "type": type,
            "events": [],
            "restrictions": restrictions
        }
    }

    // Save the new venue
    await datastore.save(venue);
    res.status(201).json({
        "id": venue.key.id,
        "name": venue.data.name,
        "address": venue.data.address,
        "type": venue.data.type,
        "events": venue.data.events,
        "restrictions": venue.data.restrictions,
        "self": req.protocol + "://" + req.get("host") + "/venues/" + venue.key.id
    });
});

// Read all venue
app.get('/venues', async (req, res) => {
    const page = req.query.page ? parseInt(req.query.page, 10) : 0;

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    const query = datastore
        .createQuery('venue')
        .limit(OFFSET + 1)
        .offset(OFFSET * page);

    try {
        let [venues] = await datastore.runQuery(query);

        // Construct respone and send
        venues = venues.map((venue => {
            return {
                "id": venue[datastore.KEY].id,
                ...venue,
                "self": req.protocol + "://" + req.get("host") + "/venues/" + venue[datastore.KEY].id
            }
        }));

        // Get the Venues count
        const countQuery = datastore
            .createQuery('venue')
            .select('__key__');

        const [total] = await datastore.runQuery(countQuery);


        let response = {
            "venues": venues.slice(0, 5),
            "totalCount": total.length
        };
        if (venues.length > OFFSET) {
            response.next = req.protocol + "://" + req.get("host") + "/events?page=" + (page + 1);
        }
        res.status(200).json(response);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Read single venue
app.get('/venues/:id', async (req, res) => {
    const { id } = req.params;
    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    try {
        const key = datastore.key(['venue', parseInt(id, 10)]);
        const [venue] = await datastore.get(key);

        if (!venue) {
            return res.status(404).json({"Error": "Venue not found"});
        }

        venue.self = req.protocol + "://" + req.get("host") + "/venues/" + id;

        res.status(200).json(venue);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Read venue's events
app.get('/venues/:id/events', async (req, res) => {
    const { id } = req.params;
    const accept = req.headers.accept;

    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    try {
        const key = datastore.key(['venue', parseInt(id, 10)]);
        const [venue] = await datastore.get(key);

        if (!venue) {
            return res.status(404).json({"Error": "Venue not found"});
        }

        res.status(200).json(venue.events);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Update venue
// Cannot change events from this call, use Event endpoints
app.patch('/venues/:id', async (req, res) => {
    const { id } = req.params;
    const { name, address, type, restrictions, events, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Do not handle events from the Venue, use Events calls
    if (events) {
        return res.status(400).json({"Error": "Events should be added or removed using POST /events or DELETE /events/:id"});
    }

    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    try {
        const key = datastore.key(['venue', parseInt(id, 10)]);
        const [venue] = await datastore.get(key);

        if (!venue) {
            return res.status(404).json({"Error": "Venue not found"});
        }

        if (name) {
            const venues = venueHasName(name);
            if (venues) {
                for (let i = 0; i < venues.length; i++) {
                    if (venues[i].address = venue.address) {
                        return res.status(400).json({"Error": "Venue cannot have the same name as another venue at the same address"})
                    }
                }
            }
        }

        if (address) {
            const query = datastore
                .createQuery('venue')
                .filter('address', '=', address);
            const venuesByAddr = await datastore.runQuery(query);
            for (let i = 0; i < venues.length; i++) {
                if (venuesByAddr[i].address = venue.address) {
                    return res.status(400).json({"Error": "Venue cannot have the same name as another venue at the same address"})
                }
            }
        }

        let venueData = {
            "name": name || venue.name,
            "address": address || venue.address,
            "type":type || venue.type,
            "events": venue.events,
            "restrictions": restrictions || venue.restrictions
        }

        await datastore.update({
            key: key,
            data: venueData
        });

        venueData = {
            "id": id,
            ...venueData,
            "self": req.protocol + "://" + req.get("host") + "/venues/" + venue[datastore.KEY].id
        }

        res.status(200).json(venueData);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Cannot change events from this call, use Event endpoints
app.put('/venues/:id', async (req, res) => {
    const { id } = req.params;
    const { name, address, type, restrictions, events, ...other } = req.body;
    const contentType = req.headers['content-type'];

    if (!contentType || contentType !== 'application/json') {
        return res.status(415).json({
            "Error": "The request body is in an unsupported media type. Request body must be JSON"
        });
    }

    const accept = req.headers.accept;
    if (!accept || (!accept.includes('application/json') && !accept.includes('*/*'))) {
        return res.status(406).json({ "Error": "Request is for an invalid media type" });
    }

    // Do not handle events from the Venue, use Events calls
    if (events) {
        return res.status(400).json({"Error": "Events should be added or removed using POST /events or DELETE /events/:id"});
    }

    if (Object.keys(other).length > 0) {
        return res.status(400).json({"Error": "Invalid attribute"});
    }

    if (!name || !address || !type || !restrictions) {
        return res.status(400).json({
            "Error": "Missing attribute from request"
        }); 
    }

    try {
        const key = datastore.key(['venue', parseInt(id, 10)]);
        const [venue] = await datastore.get(key);

        if (!venue) {
            return res.status(404).json({"Error": "Venue not found"});
        }

        const [venues] = venueHasName(name);
        for (let i = 0; i < venues.length; i++) {
            if (venues[i].address = venue.address) {
                return res.status(400).json({"Error": "Venue cannot have the same name as another venue at the same address"})
            }
        }

        const addressquery = datastore
            .createQuery('venue')
            .filter('address', '=', address);
        const venuesByAddr = await datastore.runQuery(addressquery);
        for (let i = 0; i < venues.length; i++) {
            if (venuesByAddr[i].address = venue.address) {
                return res.status(400).json({"Error": "Venue cannot have the same name as another venue at the same address"})
            }
        }

        const venueData = {
            "name": name || venue.name,
            "address": address || venue.address,
            "type":type || venue.type,
            "events": venue.events,
            "restrictions": restrictions || venue.restrictions
        }

        await datastore.update({
            key: key,
            data: venueData
        })

        res.status(200).json(venueData);
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

// Delete venue
app.delete('/venues/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const key = datastore.key(['venue', parseInt(id, 10)]);
        const [venue] = await datastore.get(key);

        if (!venue) {
            return res.status(404).json({"Error": "Venue not found"});
        }

        await datastore.delete(key);
        res.status(204).end();
    } catch (err) {
        console.error('Error:', err);
        res.status(500).json({"Error": "Internal Server Error"});
    }
});

/*
The front end handles user accounts by using Auth0.
Allows users to sign in using their Auth0 account and only the needed data is copied to datastore
If user is not yet in Datastore they are added, otherwise skip right to user page
*/

// Front end
app.get('/', async (req, res) => {
    if (req.oidc.isAuthenticated()) {
        let tickets = '<p>No tickets yet!</p>';
        
        // After logging in, check if user exists in datastore
        let existingUser = await getUserByEmail(req.oidc.user.email);
    
        if (!existingUser) {
            const user = {
                key: datastore.key('user'),
                data: {
                    "name": req.oidc.user.name,
                    "email": req.oidc.user.email,
                    "phone": null,
                    "tickets": []
                }
            }
            await datastore.save(user);
            existingUser = await getUserByEmail(req.oidc.user.email);
        } else {
            if (existingUser.tickets.length > 0) {
                tickets = '<p>Tickets:<br>' 
                for (let i = 0; i < existingUser.tickets.length; i++) {
                    tickets += `${existingUser.tickets}<br>`
                }
                tickets += '</p>'
            }
        }

        // Send page
        res.send(
`<h1>Portfolio project</h1>
<h2>Brian Thomas</h2>
<p>Logged in as ${req.oidc.user.name}</p>
<p>ID: ${existingUser[datastore.KEY].id}</p>
<a href="/logout">Logout</a><br>
<p id="accountInfoText" onclick="toggleAccountInfo()"><u>Account JWT</u> (click to show)</p>
<div id="accountInfo" style="display: none; word-wrap: break-word">${req.oidc.idToken}</div>
${tickets}
<script>
  function toggleAccountInfo() {
    const accountInfoDiv = document.getElementById("accountInfo");
    const accountInfoText = document.getElementById("accountInfoText");

    if (accountInfoDiv.style.display === "none") {
      accountInfoDiv.style.display = "block";
      accountInfoText.innerHTML = "<u>Account JWT</u> (click to hide)";
    } else {
      accountInfoDiv.style.display = "none";
      accountInfoText.innerHTML = "<u>Account JWT</u> (click to show)";
    }
  }
</script>`
        );
    } else {
        res.sendFile(__dirname + '/views/index.html');
    }
});

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
   console.log(`Server listening on port ${PORT}`); 
});