import React, { useState, useEffect, useCallback } from 'react';
import IncomingMessage from '../Components/IncomingMessage';
import OutgoingMessage from '../Components/OutgoingMessage';
import { useSocket } from '../context/SocketContext';
import Sidebar from '../Components/Sidebar';
import axios from 'axios';

function Chat() {
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const socket = useSocket();

    useEffect(() => {
        const fetchMessages = async () => {
            try {
                const userId = localStorage.getItem('userId');
                const response = await axios.get(`http://localhost:8080/messages/${userId}`);
                const fetchedMessages = response.data.messages.map(msg => ({
                    ...msg,
                    type: 'client' // Marking messages fetched from server initially as client messages
                }));
                setMessages(fetchedMessages);
                localStorage.setItem('chatMessages', JSON.stringify(fetchedMessages));
            } catch (error) {
                console.error('Error fetching messages:', error.message);
            }
        };

        fetchMessages();
    }, []);

    const handleSendMessage = () => {
        if (newMessage.trim()) {
            const messageObject = {
                userId: localStorage.getItem('userId'), 
                content: newMessage,
                timestamp: new Date().toISOString(),
                type: 'client', // Mark as client message when sending
            };

            if (socket) {
                socket.emit('outgoing-message', messageObject);
            }

            const updatedMessages = [...messages, messageObject];
            setMessages(updatedMessages);
            localStorage.setItem('chatMessages', JSON.stringify(updatedMessages));
            setNewMessage('');
        }
    };

    const handleIncomingMessage = useCallback(
        (message) => {
            const updatedMessages = [...messages, {
                ...message,
                type: 'server' // Mark as server message when receiving
            }];
            setMessages(updatedMessages);
            localStorage.setItem('chatMessages', JSON.stringify(updatedMessages));
        },
        [messages]
    );

    useEffect(() => {
        if (socket) {
            socket.on('incoming-message', handleIncomingMessage);

            return () => socket.off('incoming-message', handleIncomingMessage);
        }
    }, [socket, handleIncomingMessage]);

    return (
        <div className="flex h-screen">
            <Sidebar />

            <div className="w-3/4 flex flex-col bg-white shadow-lg overflow-hidden">
                <div className="px-4 py-2 bg-gray-800 text-white text-lg">Chat Messages</div>
                <div className="p-4 h-80 overflow-y-auto flex-grow">
                    {messages.map((msg, index) => (
                        msg.type === 'client' ? (
                            <OutgoingMessage message={msg.content} key={index} />
                        ) : (
                            <IncomingMessage message={msg.content} key={index} />
                        )
                    ))}
                </div>

                <div className="flex p-4 border-t">
                    <input
                        type="text"
                        value={newMessage}
                        onChange={(e) => setNewMessage(e.target.value)}
                        className="flex-1 px-2 py-1 border rounded"
                        placeholder="Type your message..."
                    />
                    <button
                        onClick={handleSendMessage}
                        className="ml-2 px-4 py-1 bg-blue-500 text-white rounded"
                    >
                        Send
                    </button>
                </div>
            </div>
        </div>
    );
}

export default Chat;
