const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https://api.gofood.com'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

const ALLOWED_ORIGIN = process.env.SPA_ORIGIN || 'https://app.gofood.com';
app.use(cors({
  origin: ALLOWED_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false }));
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: { error: 'Muitas tentativas. Tente novamente mais tarde.' },
});

const { router: authRouter } = require('./auth');
const ordersRouter = require('./orders');

app.use('/api/auth/login', loginLimiter);
app.use('/api/auth', authRouter);
app.use('/api', ordersRouter);

// rota /me: servidor decide o role (Q6)
const jwtMe = require('jsonwebtoken');
app.get('/api/me', (req,res)=>{
  const t=req.cookies?.access_token; if(!t) return res.status(401).json({error:'nao auth'});
  try{ const p=jwtMe.verify(t, process.env.JWT_ACCESS_SECRET); return res.json({user:{id:p.sub}, role:p.role}); }
  catch{ return res.status(401).json({error:'invalido'}); }
});

app.use((req, res) => res.status(404).json({ error: 'Não encontrado' }));

app.use((err, req, res, next) => {
  console.error(err);
  const body = { error: 'Erro interno' };
  if (process.env.NODE_ENV !== 'production') body.detail = err.message;
  res.status(err.status || 500).json(body);
});

app.listen(process.env.PORT || 3000, () => console.log('GoFood API no ar'));
