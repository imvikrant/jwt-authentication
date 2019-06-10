const jwt = require('jsonwebtoken')
const User = require('../models/User')

const auth = async (req, res, next) => {
    try {

        // check if the request has header - Authoriazation
        if (!req.header('Authorization')) {
            throw new Error('Authentication header error')
        }
        
        const token = req.header('Authorization').replace('Bearer ', '')
        const decoded = jwt.verify(token, 'hello') // verifies the jwt on the request object
        const user = await User.findOne({ _id: decoded._id, 'tokens.token': token})

        if (!user) {
            throw new Error('Authentication failed')
        }

        // adds the user associated with the token to the request object
        req.user = user
        next()

    } catch (e) {
        res.status(401).send({error: e.message})
    }

}

module.exports = auth