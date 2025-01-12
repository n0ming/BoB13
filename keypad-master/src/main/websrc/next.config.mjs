/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:8080/api/keypad/:path*' // 백엔드의 경로에 맞게 수정
      },
    ]
  },
  reactStrictMode: true,
};

export default nextConfig;
