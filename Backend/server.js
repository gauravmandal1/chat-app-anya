import express from 'express';
import http from 'http';
import { Server as SocketServer } from 'socket.io';
import cors from 'cors';
import mongoose from 'mongoose';

const app = express();
const server = http.createServer(app);
const io = new SocketServer(server, {
    cors: {
        origin: 'http://localhost:5173',
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type'],
        credentials: true,
    }
});


app.use(cors());
app.use(express.json());


mongoose.connect('mongodb+srv://runtimeTerror:u9LUu5WhKwiDY3xR@cluster0.ngoqydw.mongodb.net/chatApp');

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    messages: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Message' }],
});

const messageSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username, password }).populate('messages');

    if (user) {
        res.status(200).json({ message: 'Login successful', user });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    const newUser = new User({ username, password });
    await newUser.save();

    res.status(201).json({ message: 'Signup successful', user: newUser });
});

app.get('/messages/:userId', async (req, res) => {
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


server.listen(8080, () => console.log(`Server running on port ${8080}`));
