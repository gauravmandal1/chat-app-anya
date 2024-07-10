import express from 'express';
import http from 'http';
import { Server as SocketServer } from 'socket.io';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new SocketServer(server, {
    cors: {
        origin: process.env.CLIENT_URL || 'http://localhost:5173',
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type'],
        credentials: true,
    }
});

app.use(cors());
app.use(express.json());

// MongoDB connection with retry logic
const connectWithRetry = () => {
    mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        setTimeout(connectWithRetry, 5000); // Retry connection after 5 seconds
    });
};

connectWithRetry();

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    messages: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Message' }],
});

const messageSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// Middleware for authenticating JWT tokens
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Secure login endpoint with bcrypt and JWT
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username }).populate('messages');
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', token, user });
});

// Secure signup endpoint with bcrypt
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });

    try {
        await newUser.save();
        res.status(201).json({ message: 'Signup successful', user: newUser });
    } catch (err) {
        res.status(400).json({ message: 'Error creating user', error: err.message });
    }
});

// Retrieve messages with authentication
app.get('/messages/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;

    try {
        const messages = await Message.find({ user: userId }).sort({ timestamp: 'asc' });
        res.status(200).json({ messages });
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving messages', error: err.message });
    }
});

// WebSocket connection handling
io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('outgoing-message', async (data) => {
        console.log('Received outgoing message:', data);

        try {
            const newMessage = new Message({
                user: data.userId,
                content: data.content,
            });

            await newMessage.save();

            // Update user's messages array with new message ID
            await User.findByIdAndUpdate(data.userId, { $push: { messages: newMessage._id } });

            io.emit('incoming-message', newMessage);
        } catch (error) {
            console.error('Error saving message:', error.message);
        }
    });

    socket.on('disconnect', () => console.log('User disconnected'));
});

// Handle uncaught exceptions and unhandled rejections
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
