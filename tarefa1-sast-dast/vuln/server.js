const express = require('express');
const cors = require('cors');
const app = express();
const { router: authRouter } = require('./auth');
const ordersRouter = require('./orders');

app.use(cors());              // V16
app.use(express.json());      // V17
// V18 sem rate limiting
// V19 sem helmet

app.use('/api', authRouter);
app.use('/api', ordersRouter);

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });  // V20
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('VULN server on ' + PORT));
