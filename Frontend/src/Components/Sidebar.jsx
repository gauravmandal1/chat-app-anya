import React from 'react';
import { useNavigate } from 'react-router-dom';

function Sidebar() {
    const navigate = useNavigate(); 

    const handleLogoutClick = () => {
        localStorage.removeItem('userId');
        localStorage.removeItem('username');
        navigate('/login'); 
    };

    return (
        <div className="w-1/4 bg-gray-800 text-white flex flex-col">
            <div className="px-4 py-2 text-lg border-b border-gray-700">Sidebar</div>
            <div className="flex-grow flex items-center justify-center">
                <button
                    className="px-4 py-2 bg-red-500 text-white rounded"
                    onClick={handleLogoutClick}
                >
                    Logout
                </button>
            </div>
        </div>
    );
}

export default Sidebar;
