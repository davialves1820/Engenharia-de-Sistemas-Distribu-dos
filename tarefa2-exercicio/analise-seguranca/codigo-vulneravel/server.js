const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());              // V16
app.use(express.json());      // V17

// V18 sem rate limiting
// V19 sem helmet

app.use('/api', authRouter);
app.use('/api', ordersRouter);

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });  // V20
});

app.listen(3000);
