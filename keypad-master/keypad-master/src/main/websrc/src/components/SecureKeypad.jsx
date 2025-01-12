"use client";

import React from 'react';
import useSecureKeypad from '../hooks/useSecureKeypad';
import KeypadUserInput from './KeypadUserInput';
import '../style/keypad.css';

const SecureKeypad = () => {
    const { keypadData, handleClick, userInput } = useSecureKeypad();

    if (!keypadData) {
        return <div>Loading...</div>;
    }

    return (
        <div className="keypad-container">
            <h1>Secure Keypad</h1>
            <KeypadUserInput count={userInput.length} />
            <div className="keypad-background">
                <img
                    src={`data:image/png;base64,${keypadData.image}`}
                    alt="Keypad"
                    onClick={handleClick}
                    className="keypad-image"
                />
            </div>
        </div>
    );
};

export default SecureKeypad;
