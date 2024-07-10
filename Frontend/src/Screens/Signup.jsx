import React, { useState } from 'react';
import InputComponent from '../Components/InputComponent';
import ButtonComponent from '../Components/ButtonComponent';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Signup() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();

    const handleUsername = (e) => setUsername(e.target.value);
    const handlePassword = (e) => setPassword(e.target.value);

    const handleSubmit = async () => {
        try {
            const response = await axios.post(`${process.env.REACT_APP_API_URL}/signup`, {
                username,
                password,
            });

            const { user, message } = response.data;
            console.log(message); // Log success message or handle it as needed

            localStorage.setItem('userId', user._id);
            localStorage.setItem('username', user.username);

            navigate("/chat");

        } catch (error) {
            console.error('Signup failed:', error.message);
        }
    };

    return (
        <>
            <div className='flex flex-col gap-6 sm:max-w-xl mx-auto h-screen justify-center p-4 sm:p-6 md:p-8'>

                <h1 className="text-2xl font-bold text-gray-900 sm:text-3xl md:text-4xl text-center mb-3 sm:mb-6 md:mb-8 lg:mb-10">
                    Create an Account
                </h1>

                <InputComponent placeholder={"Username"} type={"text"} handleInput={handleUsername} />
                <InputComponent placeholder={"Password"} type={"password"} handleInput={handlePassword} />

                <ButtonComponent text={"Sign Up"} handleSubmit={handleSubmit} />

                <p className="mt-4 text-sm text-gray-500 text-center">
                    Already have an account?
                    <a href="/login" className="text-gray-700 font-semibold ml-1">Log in</a>.
                </p>

            </div>
        </>
    );
}

export default Signup;
