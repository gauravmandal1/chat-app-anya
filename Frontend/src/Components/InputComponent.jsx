import React from 'react';

function InputComponent({ placeholder, handleInput, type }) {
    return (
        <>
            <label
                htmlFor={placeholder}
                className="relative block rounded-md border border-gray-200 shadow-sm focus-within:border-blue-600 focus-within:ring-1 focus-within:ring-blue-600"
            >
                <input
                    type={type}
                    id={placeholder}
                    className="h-8 sm:h-12 lg:h-11 md:h-10 px-3 py-2 w-full text-sm md:text-md lg:text-lg peer border-none bg-transparent placeholder-transparent focus:border-transparent focus:outline-none focus:ring-0"
                    placeholder={placeholder}
                    onChange={handleInput}
                />
                <span
                    className="pointer-events-none absolute left-2.5 top-0 -translate-y-1/2 bg-white px-1 text-xs text-gray-700 transition-all peer-placeholder-shown:top-1/2 peer-placeholder-shown:text-base peer-focus:top-0 peer-focus:text-xs peer-focus:text-gray-500"
                >
                    {placeholder}
                </span>
            </label>
        </>
    );
}

export default InputComponent;
