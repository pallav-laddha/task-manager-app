const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
    name: {
        type: String,
        trim:true
    },
    password: {
        type: String,
        required: true,
        trim: true,
        validate(value) {
            if(value.length <6){
                throw new Error ('password should be greater than 6 character')
            }

            if(value.includes('password')){
                throw new Error ('password cannot be password')
            }
        }
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        validate(value) {
            if(!validator.isEmail(value)){
                throw new Error ('Email is not valid')
            }
        }
    },
    age: {
        type: Number
    },
    tokens: [{
        token: {
            type: String,
            require: true
        }
    }]
})

userSchema.methods.toJSON = function(){
    user = this
    const userobject = user

    delete userobject.password
    delete userobject.tokens

    return userobject
}

userSchema.methods.generateAuthToken =async function() {
    const user = this
    const token = jwt.sign({_id: user._id.toString() }, 'thisismynewcourse')
    user.tokens = user.tokens.concat({ token })
    await user.save()
    return token
}

userSchema.statics.findByCredentials = async (email, password) =>{
    const user = await User.findOne({email})
    
    if(!user){
        throw new Error('Unable to login')
    }
    
    const isMatch = await bcrypt.compare(password, user.password)
    if(!isMatch){
        throw new Error('Unable to login')
    }
    return user
}

userSchema.pre('save', async function(next) {
    const user = this

    if(user.isModified('password')){
        user.password = await bcrypt.hash(user.password, 8)
    }
    next()
})

 const User = mongoose.model('User', userSchema)

module.exports = User