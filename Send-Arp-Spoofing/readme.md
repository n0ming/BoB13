## 🧭 Overview
이 프로그램은 ARP(Address Resolution Protocol)의 신뢰 기반 통신 구조를 악용하여, 동일 네트워크 상의 호스트 간 트래픽 흐름을 제어할 수 있도록 설계된 네트워크 분석 및 중간자 트래픽 릴레이 도구입니다. 

ARP Spoofing을 통해 패킷을 스니핑하거나 중계하며, 복수의 (sender, target) 흐름을 병렬적으로 처리할 수 있도록 구현되어 있습니다.

본 프로젝트는 이론적인 네트워크 구조와 실전 보안 관점 양쪽을 아우르며, ARP 프로토콜의 구조적 허점을 기반으로 작동합니다.

## 🔍 Background
Ethernet 기반의 네트워크 환경에서 ARP는 IP 주소에 대응하는 MAC 주소를 알려주는 프로토콜로, 응답자와 요청자의 신원을 별다른 인증 없이 처리합니다. 

이 구조는 편리하지만, 신뢰 기반이라는 특성상 악의적인 공격자에게 노출되기 쉬운 취약점을 가지고 있습니다.

이 도구는 다음과 같은 상황을 가정하여 동작합니다:
- 동일한 L2 네트워크에 연결된 여러 호스트 존재
- 공격자가 Promiscuous 모드로 동작하며 ARP Table을 감염시킴
- Sender → Attacker → Target의 흐름을 Relay IP Packet 방식으로 중계함
- 감염 해제가 탐지되면 재감염(Infect)을 수행함

## ⚙️ Features
### 1. ARP 감염 및 유지 (ARP Infection)
ARP Reply 패킷을 통해 sender의 ARP table을 지속적으로 감염시킴

감염 해제 상황(ARP Recover)을 감지하여 즉시 재감염 수행

### 2. Packet Relay
감염된 sender가 전송한 IP 패킷을 분석하고, 올바르게 target에게 relay

Ethernet 헤더를 조작하여 중간자의 역할을 수행함

### 3. 멀티 흐름 지원
복수의 (sender, target) pair를 입력받아 각 흐름을 별도의 스레드로 병렬 처리

실시간 네트워크 제어 환경에서 안정적으로 작동

### 4. MAC Address Resolution
송신 대상의 MAC 주소를 동적으로 확인하기 위해 ARP 요청을 보내고 응답을 수신함

### 5. 디버깅 및 시간 기록 기능
패킷 흐름의 타이밍과 상태를 실시간으로 확인할 수 있도록 타임스탬프 출력 제공

## 🧩 Technical Highlights
- pcap 기반의 실시간 패킷 캡처 및 송신
- Promiscuous Mode를 통한 모든 패킷 수신
- MAC/IP 주소 맵핑 관리를 통한 흐름 구성
- EthHdr / ArpHdr / IpHdr 등 직접 정의한 프로토콜 헤더 구조체 사용
- 멀티스레딩을 이용한 비동기 흐름 처리

## 📦 Build & Run 
### 🔧 Requirements
- Linux 환경
- libpcap 개발 라이브러리

### 🏗️ Build & Run
```bash
make
sudo ./arp-spoofing <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sudo ./arp-spoofing eth0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```

## 실행 사진
### target Mac 주소
![image](https://github.com/user-attachments/assets/56d2bc5e-f8ba-4e4a-b092-938101c4b6b2)

### 공격 실행 결과
![image](https://github.com/user-attachments/assets/6ff55960-6960-4fd3-aca5-5446c51327e0)
- 실제로 target한 테블릿에 대한 정보가 wireshark를 통해서 패킷을 스니핑할 수 있었음
- https가 아닌 http 보안이 낮은 웹페이지에 접근하면 해당 데이터가 패킷을 통해 확인이 가능했음
