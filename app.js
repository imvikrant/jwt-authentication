const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs')

const User = require('./models/User') // mongoose user model
const auth = require('./middlewares/auth') // custom middleware for authentication

const app = express();
app.use(bodyParser.json());

const port = process.env.PORT;

// provide the url string in the .env file in root folder of the project
const mongodbConnectionURL = process.env.MONGODB_CONNECTION_URL;

mongoose.connect(mongodbConnectionURL, {useNewUrlParser: true});

// register route which accepts username email and password and sends back auth token on success
app.post('/register', async (req, res) => {
    const {username, email, password } = req.body
    const user = new User({username, email, password})

    try {
        const savedUser = await user.save()
        const token = await savedUser.generateAuthToken()
        res.json(token)

    } catch (error) {
        res.status(401).send(error)
    }
})


// login route which accepts email and password and sends back auth token on success
app.post('/login', async (req, res) => {
    const { email, password } = req.body
    
    try {
        const user = await User.findOne({email})
        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch)
            throw new Error('invalid email or password')

        const token = await user.generateAuthToken();
        res.json(token)
    }
    catch(error) {
        res.send(error.message)
    }
})

// logout by removing the token from the user object
app.get('/logout', auth, async (req, res) => {
    const token = req.header('Authorization').replace('Bearer ', '')

    const user = req.user;
    await user.removeAuthToken(token);

    res.send('Logout Success')

})


// route that works only after authenticaton 
app.get('/users', auth, (req, res) => {
    const { username } = req.user
    res.send(`hello ${username}`)
})

// sends error code and message for all other routes
app.get('*', (req, res) => {
    res.status(401).send('The requested path does not exist')
})

// listens to PORT env variable
app.listen(port, () => {
    console.log(`Authentication server is listening on port ${port}`)
})