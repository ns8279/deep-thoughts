const jwt = require('jsonwebtoken');

const secret = 'mysecretssshhhh';
const expiration = '2h';

module.exports = {
    signToken: function({ username, email, _id }) {
        const payload = { username, email, _id};

        return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
    },

    authMiddleware: function({ req }) {
        //allows token to be sent via rq.body, req.query, or headers
        let token = req.body.token || req.query.token || req.headers.authorization; 

        //separate the "Bearer" from the "<tokenValue>"
        if(req.headers.authorization) {
            token = token
                .split(' ')
                .pop()
                .trim();
        }

        //if no token retuen request object
        if(!token) {
            return req;
        }

        try{
            //decode and attach user data to the req object
            const { data } = jwt.verify(token, secret, { maxAge: expiration });
            req.user = data;
        }
        catch{
            console.log('Invalid token');
        }

        //return updated request object
        return req;
    }
};