const router = require('express').Router()
const User = require('../model/User')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const {registerValidation, loginValidation} = require('../validation')

router.post('/register', async (req, res) => {
    //Validate the data before we use
    const { error } = registerValidation(req.body)
    if (error) {
        return res.status(400).send(error.details[0].message)
    }

    //Checking if user already in the database
    const emailExist = await User.findOne({
        email: req.body.email
    })

    if (emailExist) {
        return res.status(400).send('Email already exists')
    }

    //Hash the password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(req.body.password, salt)

    //Create a new user
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    })
    try {
        const savedUser = await user.save()
        res.send({ user: user._id })
    } catch(err) {
        res.status(400).send(err)
    }
})

//Login
router.post('/login', async (req, res) => {
    //Validate the data before we use
    const { error } = loginValidation(req.body)
    if (error) {
        return res.status(400).send(error.details[0].message)
    }

    //Checking if user already in the database
    const user = await User.findOne({
        email: req.body.email
    })

    if (!user) {
        return res.status(400).send('Email/Password not correct')
    }
    const validPass = await bcrypt.compare(req.body.password, user.password)
    
    if (!validPass) {
        return res.status(400).send('Email/Password not correct')
    }

    //Create and assign a token
    const token = jwt.sign({ _id: user._id }, process.env.TOKEN_SECRET)
    res.header('auth-token', token).send(token)
})

module.exports = router