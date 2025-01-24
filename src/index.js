const express = require('express')
const path = require('path')
const cors = require('cors')
const bodyParser = require('body-parser')
const validate = require('./middleware/Validate.js')

const app = express()
app.use(express.static(path.join(__dirname, 'public')))
app.use(cors())
app.use(bodyParser.json())

app.post('/api/validate', validate, (req, res) => {
  res.json(req.payload)
})

const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})
