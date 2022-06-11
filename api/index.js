const express = require('express')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

let refreshTokensArr = []
const privateKey = 'mySecretKey'
const refreshKey = 'myRefreshSecretKey'

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

const generateAccessToken = (user) => {

    const {id, isAdmin} = user
    return jwt.sign(
        {id, isAdmin},
        privateKey,
        {expiresIn: '15m'} // токен действителен 15мин.
    )

}
const generateRefreshToken = (user) => {
    const {id, isAdmin} = user
    return jwt.sign(
        {id, isAdmin},
        refreshKey,
    )
}

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

app.post('/api/login', async (req, res) => {
    const {username, password} = req.body
    const user = users.find(i => i.username === username && i.password === password)

    if (user) {
        //Generate access token
        const accessToken = await generateAccessToken(user)
        const refreshToken = await generateRefreshToken(user)
        refreshTokensArr.push(refreshToken)

        return res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken,
        })
    }

    return res.status(400).json('Username or password incorrect!')
})

app.post('/api/logout', verify, async (req, res) => {
    const refreshToken = req.body.token
    refreshTokensArr = refreshTokensArr.filter(i => i !== refreshToken)
    res.status(200).json('You logged out successfully.')
})

app.post('/api/refresh', (req, res) => {
    //take the refresh token from the user
    const refreshToken = req.body.token

    //send error if there is no token or it`s invalid
    if (!refreshToken) return res.status(401).json('You are not authenticated!')
    if (!refreshTokensArr.includes(refreshToken)) return res.status(403).json('Refresh token is not valid!')

    jwt.verify(refreshToken, refreshKey, (err, user) => {
        err && console.log(err)
        refreshTokensArr = refreshTokensArr.filter(i => i !== refreshToken)

        const newAccessToken = generateAccessToken(user)
        const newRefreshToken = generateRefreshToken(user)

        refreshTokensArr.push(newRefreshToken)

        return res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        })
    })

    //if everything is ok, create new access token, refresh token and send to user
})

app.delete('/api/users/:userId', verify, (req, res) => {
    if (req.user.id === req.params.userId || req.user.isAdmin) {
        return res.status(200).json('User has been deleted.')
    }

    return res.status(403).json('You are not allowed to delete this user!')
})

app.listen(5000, () => {
    console.log('Backend server is running!')
})