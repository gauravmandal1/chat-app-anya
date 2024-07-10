import React from 'react';
import formateDate from './formateDate';

function IncomingMessage({ name = "Server", message }) {
    return (
        <div className="my-2 p-3 border rounded-lg bg-blue-100 text-left max-w-xs sm:max-w-sm md:max-w-md lg:max-w-lg xl:max-w-xl ml-0 mr-auto shadow-md">
            <div className="text-sm font-semibold text-blue-600">{name}</div>
            <div className="mt-1 text-lg text-black">{message}</div>
            <div className="text-xs text-gray-500 mt-1">{formateDate}</div>
        </div>
    );
}

export default IncomingMessage;
