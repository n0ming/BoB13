// src/app/page.jsx
"use client"; // Add this line if this component uses Client Components

import React from 'react';
import SecureKeypad from '../components/SecureKeypad.jsx';

const Page = () => {
    return (
        <div>
            <SecureKeypad />
        </div>
    );
};

export default Page;
