const express = require('express')
const path = require('path')
const cors = require('cors')

const app = express()
app.use(express.static(path.join(__dirname, 'public')))
app.use(cors())

app.get('/api/healthcheck', (req, res) => {
  res.json({ message: 'Hello, World!' })
})

const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log(`Server running on port ${port}`)
})
