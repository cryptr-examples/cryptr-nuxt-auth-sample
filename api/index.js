const bodyParser = require('body-parser')
const app = require('express')()

app.use(bodyParser.json())
app.all('/logout', function (req, res) {
  console.log('req', req)
  console.log('res', res)
});

module.exports = app
