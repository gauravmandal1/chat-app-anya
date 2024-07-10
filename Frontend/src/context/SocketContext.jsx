import React, { createContext, useContext, useEffect, useState } from "react";
import socketIO from 'socket.io-client';

const SocketContext = createContext(null);

const useSocket = () => useContext(SocketContext);

const SocketContextProvider = ({ children }) => {
    const [socket, setSocket] = useState(null);

    useEffect(() => {
        const socketInstance = socketIO.connect(`${process.env.REACT_APP_API_URL}`);

        socketInstance.on('connect', () => {
            console.log('Socket connected');
            setSocket(socketInstance);
        });

        socketInstance.on('connect_error', (error) => {
            console.error('Socket connection error:', error);
        });

        socketInstance.on('disconnect', () => {
            console.log('Socket disconnected');
            setSocket(null); // Handle disconnection
        });

        return () => {
            console.log('Disconnecting socket');
            localStorage.removeItem("serverMessages"); // when we close the session we delete the messages from the server 
            socketInstance.disconnect(); // Clean up socket on unmount
        };
    }, []);

    return (
        <SocketContext.Provider value={socket}>
            {children}
        </SocketContext.Provider>
    );
};

export { SocketContextProvider, useSocket };
