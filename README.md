# Simple Launcher Service
윈도우 서비스 예시로 만든 Simple Launcher Service 입니다.
* 윈도우 서비스 실행 시 Explorer 권한으로 특정 프로세스 실행 ( 샘플은 메모장 실행 )
* 단일 세션으로 동작한다고 가정
* Watchdog 제공하지 않음

## 사용법
* WorkThread() 함수에서 프로세스 경로 지정
* 설치: LauncherService.exe --install
* 실행: LauncherService.exe --start
* 중지: LauncherService.exe --stop
* 제거: LauncherService.exe --uninstall

## 개발 환경
* Visual Studio 2019 ( MT Build )
* spdlog v1.12.0 ( Static Library - Visual Studio 2019 MT Build )

## License
* MIT License
