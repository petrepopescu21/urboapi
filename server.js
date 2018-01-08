if (process.env.PRODUCTION == false)
    require('dotenv').config()

var jwt = require('jsonwebtoken')
var fs = require('fs')
var azure = require('azure-storage')
var path = require('path')
var tableSvc = azure.createTableService()


const Express = require('express')
const app = Express()

var cookieParser = require('cookie-parser')
var bodyParser = require('body-parser')

var mustacheExpress = require('mustache-express');

app.engine('mustache', mustacheExpress());

app.set('view engine', 'mustache');
app.set('views', __dirname + '/views');

app.use(cookieParser())
app.use(bodyParser.json())

app.use(Express.static(path.join(__dirname, 'public')));


app.use('*', async(req, res, next) => {

    var cookie = req.cookies.jwtoken
    req.jwt = cookie
    var code = req.query.code
    if (cookie === undefined) {
        console.log("Cookie undefined")
        if (code == undefined) {
            req.result = 2
            next()
        } else {
            console.log("Trying to generate new token")
            var token = await generateToken(code)
            console.log("Token generated: " + token)
            console.log("If above null, code invalid")
            if (token !== null) {
                res.cookie("jwtoken", token)
                req.result = 1
                next()
            } else {
                req.result = 2
                next()
            }
        }
    } else {
        console.log("Token cookie present")
        var valid = checkToken(cookie)
        if (valid == false) {
            var token = await refreshToken(cookie)
            if (token != null) {
                res.cookie("jwtoken", token)
                req.jwt = token
                req.result = 0
                next()
            } else {
                res.clearCookie("jwtoken")
                req.result = 2
                next()
            }
        } else {
            req.result = 0
            next()
        }
    }
})

app.all('/private/*', function(req, res, next) {
    if (req.result == 0) {
      next(); // allow the next route to run
    } else {
      // require the user to log in
      res.redirect("/"); 
    }
})

app.use('/private', Express.static(path.join(__dirname, 'private')))

app.get('/',(req,res,next)=>{
    if(req.result == 0)
        req.name = jwt.verify(req.jwt, 'somesecret').name
    next()
})

app.get('/',(req,res)=>{
    console.log("Logic result is: "+req.result)
    if (req.result == 0)
        res.render('main',{name:req.name})
    if (req.result == 1)
        res.redirect(302,'/')
    if (req.result == 2)
        res.render('soon')
})



function checkToken(token) {
    try {
        var decoded = jwt.verify(token, 'somesecret')
        console.log("Token not expired")
        return true
    } catch (err) {
        //console.log(err)
        return false
    }
}

async function generateToken(code) {

    try {
        var result = await checkCode(code)

    } catch (err) {
        console.log("Error checking code")
        return null
    }

    var payload = {
        name: {
            first: result.FName._,
            last: result.LName._
        },
        code: code
    }
    console.log(payload)
    // sign asynchronously
    var token = jwt.sign(payload, "somesecret", {
        expiresIn: 10
    })
    return token

}

async function refreshToken(token) {
    console.log("Checking if expired")
    try {
        var decodedToken = jwt.verify(token, 'somesecret', {
            ignoreExpiration: true
        })
        console.log("Token expired, trying out code again")
        //console.log(decodedToken)
        var newToken = await generateToken(decodedToken.code)
        if (newToken == null)
            throw new Error("Code invalid")
        else {
            console.log('New Token is ' + newToken)
            console.log("Code still valid, sending back new token")
            return newToken
        }

    } catch (err) {
        console.log(err)
        console.log("Code no longer valid, returning bad response")
        return null
    }

}

function checkCode(code) {
    return new Promise(function (resolve, reject) {

        tableSvc.retrieveEntity('codes', 'codes', code, function (error, result, response) {
            if (!error) {
                resolve(result)
            } else {
                reject(error)
            }
        })
    })

}

app.listen(process.env.PORT || 80)