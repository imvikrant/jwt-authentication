const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        trim: true,
    },

    email: {
        type: String,
        required: true,
        validate: (value) => {
            if (!validator.isEmail(value))
                throw new Error('Invalid Email')
        }
    },

    password: {
        type: String,
        required: true,
        minlength: 8
    }, 

    tokens: [{
        token: {
            type: String,
            required: true,
        }
    }]
})


// hash the password before saving to database or updating it
userSchema.pre('save', async function (next) {
    const user = this;

    if (user.isModified('password')) // check if password is altered or updated
        user.password = await bcrypt.hash(user.password, 8)
    next();
})


// generates and stores auth token for user
userSchema.methods.generateAuthToken = async function () {
    const user = this

    // generates a new jwt token
    const token = jwt.sign({ _id: user._id.toString()}, 'hello')

    user.tokens = user.tokens.concat({token})
    await user.save()

    return token
}

userSchema.methods.removeAuthToken = async function (tokenToRemove) {
    const user = this

    user.tokens = user.tokens.filter(token => token.token != tokenToRemove)

    await user.save()
}

const User = mongoose.model('users', userSchema);

module.exports =  User;

