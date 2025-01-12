import React from 'react';
import '../style/keypad.css';

const KeypadUserInput = ({ count }) => {
    const totalDots = 6;
    return (
        <div className="progress-indicator">
            {Array.from({ length: totalDots }).map((_, index) => (
                <div
                    key={index}
                    className={`dot ${index < count ? 'filled' : ''}`}
                />
            ))}
        </div>
    );
};

export default KeypadUserInput;
