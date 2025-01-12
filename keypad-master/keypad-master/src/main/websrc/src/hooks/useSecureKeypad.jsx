"use client";

import { useState, useEffect } from 'react';
import axios from "axios";
import { JSEncrypt } from 'jsencrypt';

export default function useSecureKeypad() {
    const [keypadData, setKeypadData] = useState(null);
    const [userInput, setUserInput] = useState([]);
    const [publicKey, setPublicKey] = useState(''); // 공개 키 상태 관리
    const maxClicks = 6; // 최대 클릭 수 설정

    useEffect(() => {
        const fetchKeypadData = async () => {
            try {
                const response = await axios.get('http://localhost:8080/api/keypad');
                setKeypadData(response.data);
            } catch (error) {
                console.error('Error fetching keypad data:', error);
            }
        };

        const fetchPublicKey = async () => {
            try {
                // 경로 수정: public 폴더에 위치한 공개 키 파일을 로드
                const response = await axios.get('/public_key.pem', {
                    headers: {
                        'Content-Type': 'text/plain',
                    },
                });
                setPublicKey(response.data);
            } catch (error) {
                console.error('Error fetching public key:', error);
            }
        };

        fetchKeypadData();
        fetchPublicKey();
    }, []);

    const encryptData = (data) => {
        if (!publicKey) {
            console.error('Public key is not loaded yet.');
            return null;
        }

        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKey);
        return encrypt.encrypt(data);
    };

    const sendEncryptedData = async (encryptedData) => {
        try {
            const response = await axios.post('http://localhost:8080/api/submit', { encryptedData });
            console.log('Response from server:', response.data);
        } catch (error) {
            console.error('Error sending encrypted data to server:', error);
        }
    };

    const handleClick = (event) => {
        if (userInput.length >= maxClicks) {
            console.log("Maximum number of clicks reached. Refreshing page...");
            window.location.reload(); // 페이지 새로고침
            return;
        }

        const rect = event.target.getBoundingClientRect();
        const x = event.clientX - rect.left; // X 좌표
        const y = event.clientY - rect.top;  // Y 좌표

        const row = Math.floor(y / (rect.height / 4));
        const col = Math.floor(x / (rect.width / 3));
        const index = row * 3 + col;

        const selectedHash = keypadData.hashes[index];

        if (selectedHash) {
            const updatedUserInput = [...userInput, selectedHash];
            setUserInput(updatedUserInput);

            console.log(`Clicked position: (${x}, ${y})`);
            console.log(`Grid position: row ${row}, col ${col}`);
            console.log(`Selected index: ${index}`);
            console.log(`Selected hash: ${selectedHash}`);
            console.log(`Click count: ${updatedUserInput.length}`);

            if (updatedUserInput.length === maxClicks) {
                const concatenatedHash = updatedUserInput.join('');
                console.log(`Concatenated hash: ${concatenatedHash}`);

                const encryptedData = encryptData(concatenatedHash);
                if (encryptedData) {
                    console.log(`Encrypted hash: ${encryptedData}`);

                    sendEncryptedData(encryptedData);
                }

                setTimeout(() => {
                    console.log("Maximum number of clicks reached. Refreshing page...");
                    window.location.reload();
                }, 500);
            }
        } else {
            console.log(`No hash found for position: (${x}, ${y})`);
        }
    };

    return {
        keypadData,
        handleClick,
        userInput,
    };
}
