# RFID API Demo Server

- 로그인 타입: user(24h) / admin(1h) — **최초 로그인만 OTP**
- 공통: `/assets/resolve`(스캔→관리번호), `/assets/update`(일괄 변경+검증)
- 관리자 전용: `/admin/users/search`, `/admin/users/{id}/assets`, `/admin/return-requests`
- 데모: `DEMO_MODE=1`이면 `X-Api-Key` 헤더가 필요

## Local
```bash
cp .env.example .env  # 값 채우기
npm i
npm run dev
