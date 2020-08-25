import express from 'express'
import { MongoClient, ObjectId } from 'mongodb'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import { hash, verify } from 'argon2'
import jwt from 'jsonwebtoken'
const uri = 'mongodb://localhost:27017'

const ACCESS_TOKEN_SECRET = 'superSecretAccess'
const REFRESH_TOKEN_SECRET = 'superSecretRefresh'

process.on('uncaughtException', function (err) {
  console.error(err)
})

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

var whitelist = ['http://localhost:3000']
app.use(
  cors({
    origin: whitelist,
    credentials: true,
  })
)

const auth = async (req, res, next) => {
  //get the authentication token

  const token = req.cookies.accessToken
  console.log(`access token ${token}`)
  if (!token) {
    return res.status(401).send()
  }
  try {
    const payload: any = await jwt.verify(token as any, ACCESS_TOKEN_SECRET!)
    console.log(payload)
    res.locals.user_id = payload.user_id
  } catch (err) {
    console.log(`access token invalid`)
    return res.status(401).send()
  }
  console.log(`access token valid`)
  next()
}

MongoClient.connect(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(client => {
    const db = client.db('test-db')
    app.post('/register', async (req, res) => {
      const { email, password } = req.body

      const cleanEmail = email.toLowerCase().trim()
      const users = db.collection('users')
      try {
        const existingUser = await users.findOne({ email: cleanEmail })

        if (existingUser) {
          return res.json({
            error: 'A user with this email or phone already exists.',
          })
        }
        let passwordHashed = await hash(password)
        let insertedUser = await users.insertOne({
          email: cleanEmail,
          password: passwordHashed,
        })
        console.log(insertedUser)
        const accessToken = jwt.sign(
          {
            user_id: insertedUser._id,
          },
          ACCESS_TOKEN_SECRET!,
          {
            expiresIn: '1m',
          }
        )
        const refreshToken = jwt.sign(
          {
            user_id: insertedUser._id,
          },
          REFRESH_TOKEN_SECRET!,
          {
            expiresIn: '365d',
          }
        )
        res.cookie('accessToken', accessToken, {
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : undefined,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
        })

        res.cookie('refreshToken', refreshToken, {
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : undefined,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          expires: new Date(Date.now() + 365 * 24 * 3600000),
          path: '/refresh_token',
        })

        res.status(200).send({ success: 'User Created!' })
      } catch (error) {
        console.log(error)
        res.status(500).send({ message: 'Internal Server Error' })
      }
    })

    app.post('/login', async (req, res) => {
      const { email, password } = req.body

      const cleanEmail = email.toLowerCase().trim()
      const users = db.collection('users')
      try {
        const existingUser = await users.findOne({ email: cleanEmail })
        console.log(existingUser)

        if (!existingUser || !(await verify(existingUser.password, password))) {
          return res.json({
            error: 'Incorrect Email or Password',
          })
        }

        const accessToken = jwt.sign(
          {
            user_id: existingUser._id,
          },
          ACCESS_TOKEN_SECRET!,
          {
            expiresIn: '1m',
          }
        )
        const refreshToken = jwt.sign(
          {
            user_id: existingUser._id,
          },
          REFRESH_TOKEN_SECRET!,
          {
            expiresIn: '365d',
          }
        )
        console.log('creating refrehs below')
        console.log(refreshToken)
        res.cookie('accessToken', accessToken, {
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : undefined,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          //   expires: new Date(Date.now() + 900000),
        })

        res.cookie('refreshToken', refreshToken, {
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : undefined,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          expires: new Date(Date.now() + 365 * 24 * 3600000),
          path: '/refresh_token',
        })

        res.status(200).send({ success: 'User logged in!' })
      } catch (error) {
        console.log(error)
        res.status(500).send({ message: 'Internal Server Error' })
      }
    })

    app.get('/me', auth, async (req, res) => {
      const users = db.collection('users')
      try {
        const existingUser = await users.findOne({
          _id: ObjectId(res.locals.user_id),
        })

        delete existingUser.password

        res.status(200).send({ user: existingUser })
        res.status(200)
      } catch (error) {
        console.log(error)
        res.status(500).send({ message: 'Internal Server Error' })
      }
    })

    app.post('/refresh_token', async (req, res) => {
      console.log('refresh token route')
      console.log(req.cookies)
      const refreshToken = req.cookies.refreshToken

      const setAccessToken = (res, token: string) => {
        res.cookie('accessToken', token, {
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : undefined,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
        })
      }
      if (!refreshToken) {
        setAccessToken(res, '')
        return res.status(403).send()
      }
      console.log(refreshToken)
      let payload
      try {
        payload = await jwt.verify(refreshToken, REFRESH_TOKEN_SECRET!)
      } catch (err) {
        console.log('access token error')
        setAccessToken(res, '')
        return res.status(403).send()
      }

      const accessToken = jwt.sign(
        {
          user_id: payload.user_id,
        },
        ACCESS_TOKEN_SECRET!,
        {
          expiresIn: '1m',
        }
      )
      setAccessToken(res, accessToken)
      res.status(201).send({
        success: 'Access Token created successfully',
      })
    })
  })
  .catch(console.error)

const PORT = process.env.PORT || 8080
app.listen(PORT, () => console.info(`Running on ${PORT}`))
