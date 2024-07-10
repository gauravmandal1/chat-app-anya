import React, { useState } from 'react';
import InputComponent from '../Components/InputComponent';
import ButtonComponent from '../Components/ButtonComponent';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const naviagte = useNavigate();

    const handleUsername = (e) => setUsername(e.target.value);
    const handlePassword = (e) => setPassword(e.target.value);

    const handleSubmit = async () => {
        try {
            const response = await axios.post('http://localhost:8080/login', {
                username,
                password,
            });

            const { user, message } = response.data;
            console.log(message); 
            
            localStorage.setItem('userId', user._id);
            localStorage.setItem('username', user.username);

            naviagte("/chat");
      
        } catch (error) {
            console.error('Login failed:', error.message);
        }
    };

    return (
        <>
            <div className='flex flex-col gap-6 sm:max-w-xl mx-auto h-screen justify-center p-4 sm:p-6 md:p-8'>

                <h1 className="text-2xl font-bold text-gray-900 sm:text-3xl md:text-4xl text-center mb-3 sm:mb-6 md:mb-8 lg:mb-10">
                    Welcome Back
                </h1>

                <InputComponent placeholder={"username email or phone"} type={"text"} handleInput={handleUsername} />
                <InputComponent placeholder={"password"} type={"password"} handleInput={handlePassword} />

                <ButtonComponent text={"Submit"} handleSubmit={handleSubmit} />

                <p className="mt-4 text-sm text-gray-500 text-center">
                    Don't have an account?
                    <a href="/signup" className="text-gray-700 font-semibold ml-1">Sign up</a>.
                </p>

            </div>
        </>
    );
}

export default Login;
