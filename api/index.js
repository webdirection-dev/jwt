const express = require('express')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const users = [
    {
        id: '1',
        username: 'john',
        password: 'John0908',
        isAdmin: true,
    },
    {
        id: '2',
        username: 'jane',
        password: 'Jane0908',
        isAdmin: false,
    },
]

const privateKey = 'mySecretKey'

app.post('/api/login', async (req, res) => {
    const {username: u, password: p} = req.body
    const user = users.find(i => i.username === u && i.password === p)
    const {id, username, password, isAdmin} = user

    const payload = {id, isAdmin}

    if (user) {
        //Generate access token
        const accessToken = await jwt.sign(payload, privateKey)
        return res.json({username, isAdmin, accessToken})
    }

    return res.status(400).json('Username or password incorrect!')
})

//готовим verify - функцию middleware 
const verify = (req, res, next) => {
    const authHeader = req.headers.authorization

    if (authHeader) {
        const token = authHeader.split(' ')[1]

        jwt.verify(token, privateKey, (err, user) => {
            if (err) return res.status(403).json('Token is not valid!')

            req.user = user // создали переменную user в объект реквеста
            next() // middleware отработал, передаем исполнение функции далее
        })
    } else {
        return res.status(401).json('You are not authenticated!')
    }
}

app.delete('/api/users/:userId', verify, (req, res) => {
    if (req.user.id === req.params.userId || req.user.isAdmin) {
        return res.status(200).json('User has been deleted.')
    }

    return res.status(403).json('You are not allowed to delete this user!')
})

app.listen(5000, () => {
    console.log('Backend server is running!')
})