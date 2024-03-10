#include <Windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <stdio.h>
#include <chrono>
#include <thread>
#include <vector>
#include <json/json.h>

#include "http.h"
#include "utils.h"
#include "base64.h"
#include "NtQueryInfoProc.h"

#define _CRT_SECURE_NO_WARNINGS

struct RiotStruct
{
	int port = 0;
	std::string token;
	std::string header;
	std::string version;
	std::wstring path;
};
RiotStruct rito;

struct LoLStruct
{
	int port = 0;
	std::string token;
	std::string header;
};
LoLStruct lol;

std::string WstringToString(std::wstring wstr)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;

	try
	{
		return converter.to_bytes(wstr);
	}
	catch (std::range_error)
	{
		/*std::stringstream s;
		s << wstr.c_str();
		return s.str();*/
		return "range_error";
	}
}

std::wstring GetProcessCommandLine(std::string sProcessName)
{
	std::wstring wstrResult;
	HANDLE Handle;
	DWORD ProcessID = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(snapshot, &entry))
		{
			while (Process32Next(snapshot, &entry))
			{
				char temp[260];
				sprintf(temp, "%ws", entry.szExeFile);
				if (!stricmp(temp, sProcessName.c_str()))
				{
					ProcessID = entry.th32ProcessID;
					Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);

					PROCESS_BASIC_INFORMATION pbi;
					PEB peb = { 0 };
					tNtQueryInformationProcess NtQueryInformationProcess = (tNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
					NTSTATUS status = NtQueryInformationProcess(Handle, ProcessBasicInformation, &pbi, sizeof(pbi), 0);

					if (NT_SUCCESS(status))
					{
						ReadProcessMemory(Handle, pbi.PebBaseAddress, &peb, sizeof(peb), 0);
					}
					PRTL_USER_PROCESS_PARAMETERS pRtlProcParam = peb.ProcessParameters;
					PRTL_USER_PROCESS_PARAMETERS pRtlProcParamCopy =
						(PRTL_USER_PROCESS_PARAMETERS)malloc(sizeof(RTL_USER_PROCESS_PARAMETERS));

					bool result = ReadProcessMemory(Handle,
						pRtlProcParam,
						pRtlProcParamCopy,
						sizeof(RTL_USER_PROCESS_PARAMETERS),
						NULL);
					PWSTR wBuffer = pRtlProcParamCopy->CommandLine.Buffer;
					USHORT len = pRtlProcParamCopy->CommandLine.Length;
					PWSTR wBufferCopy = (PWSTR)malloc(len);
					result = ReadProcessMemory(Handle,
						wBuffer,
						wBufferCopy,
						len,
						NULL);

					wstrResult = std::wstring(wBufferCopy);

					CloseHandle(Handle);
					break;
				}
			}
		}
	}
	CloseHandle(snapshot);
	return wstrResult;
}

static std::string Login(std::string username, std::string password, bool remember)
{
	std::string persistLogin;
	if (remember == true) persistLogin = "true"; else persistLogin = "false";
	std::string loginBody = R"({"username":")" + username + R"(","password":")" + password + R"(","persistLogin":)" + persistLogin + R"(})";
	//std::string loginBody = R"({"username":")" + username + R"(","password":")" + password + R"(","persistLogin":false})";
	//cout << "Body: " << loginBody << endl;
	return http->Request("PUT", "https://127.0.0.1/rso-auth/v1/session/credentials", loginBody, rito.header, "", "", rito.port);
}

static std::string GetSession()
{
	return http->Request("GET", "https://127.0.0.1/lol-gameflow/v1/session", "", lol.header, "", "", lol.port);
}

static std::string PostAccept()
{
	return http->Request("POST", "https://127.0.0.1/lol-matchmaking/v1/ready-check/accept", "", lol.header, "", "", lol.port);
}

static std::string GetParticipants()
{
	return http->Request("GET", "https://127.0.0.1/chat/v5/participants/", "", rito.header, "", "", rito.port);
}

static std::string GetRegion()
{
	return http->Request("GET", "https://127.0.0.1/riotclient/region-locale/", "", lol.header, "", "", lol.port);
}

std::string GetLocale()
{
	Json::Value root;
	Json::Reader reader;

	size_t foundLocale = GetRegion().find("locale");

	if (foundLocale != std::string::npos)
	{
		if (reader.parse(GetRegion(), root))
		{
			std::string locale = root["locale"].asString();
			return locale;
		}
	}
	else
	{
		return "en-US";
	}

}

void MakeRiotHeader()
{
	rito.header = "Host: 127.0.0.1:" + std::to_string(rito.port) + "\n" +
		"Connection: keep-alive" + "\n" +
		"Authorization: Basic " + rito.token + "\n" +
		"Accept: application/json" + "\n" +
		"Origin: https://127.0.0.1:" + std::to_string(rito.port) + "\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) RiotClient/11.3.356.7268 (CEF 74) Safari/537.36" + "\n" +
		"Referer: https://127.0.0.1:" + std::to_string(rito.port) + "/index.html" + "\n" +
		"Accept-Encoding: gzip, deflate, br" + "\n" +
		"Accept-Language: " + GetLocale() + ",en;q=0.8";
}

void MakeLoLHeader()
{
	lol.header = "Host: 127.0.0.1:" + std::to_string(lol.port) + "\n" +
		"Connection: keep-alive" + "\n" +
		"Authorization: Basic " + lol.token + "\n" +
		"Accept: application/json" + "\n" +
		"Content-Type: application/json" + "\n" +
		"Origin: https://127.0.0.1:" + std::to_string(lol.port) + "\n" +
		"User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) LeagueOfLegendsClient/11.3.356.7268 (CEF 74) Safari/537.36" + "\n" +
		"Referer: https://127.0.0.1:" + std::to_string(lol.port) + "/index.html" + "\n" +
		"Accept-Encoding: gzip, deflate, br" + "\n" +
		"Accept-Language: " + GetLocale() + ",en;q=0.8";
}

bool GetRiotClientInfo()
{
	std::string auth = WstringToString(GetProcessCommandLine("LeagueClientUx.exe"));
	if (auth.empty())
	{
		return 0;
	}

	std::string appPort = "--riotclient-app-port=";
	size_t nPos = auth.find(appPort);
	if (nPos != std::string::npos)
		rito.port = std::stoi(auth.substr(nPos + appPort.size(), 5)); // port is always 5 numbers long

	std::string remotingAuth = "--riotclient-auth-token="; 
	nPos = auth.find(remotingAuth) + strlen(remotingAuth.c_str());
	if (nPos != std::string::npos)
	{
		std::string token = "riot:" + auth.substr(nPos, 22); // token is always 22 chars long
		unsigned char m_Test[50];
		strncpy((char*)m_Test, token.c_str(), sizeof(m_Test));
		rito.token = base64_encode(m_Test, token.size()).c_str();
	}
	else
	{
		MessageBoxA(0, "Couldn't connect to client", 0, 0);

		return 0;
	}

	MakeRiotHeader();

	return 1;
}

bool GetLeagueClientInfo()
{
	std::string auth = WstringToString(GetProcessCommandLine("LeagueClientUx.exe"));
	if (auth.empty())
	{
		return 0;
	}

	std::string appPort = "--app-port=";
	size_t nPos = auth.find(appPort);
	if (nPos != std::string::npos)
		lol.port = std::stoi(auth.substr(nPos + appPort.size(), 5)); // port is always 5 numbers long

	std::string remotingAuth = "--remoting-auth-token=";
	nPos = auth.find(remotingAuth) + strlen(remotingAuth.c_str());
	if (nPos != std::string::npos)
	{
		std::string token = "riot:" + auth.substr(nPos, 22); // token is always 22 chars long
		unsigned char m_Test[50];
		strncpy((char*)m_Test, token.c_str(), sizeof(m_Test));
		lol.token = base64_encode(m_Test, token.size()).c_str();
	}
	else
	{
		MessageBoxA(0, "Couldn't connect to client", 0, 0);

		return 0;
	}

	MakeLoLHeader();

	return 1;
}

void GetPlayerNames(const std::string& request)
{
	Json::Value root;
	Json::Reader reader;
	std::vector<std::string> fullNames;

	size_t foundName = request.find("game_name"), foundTag = request.find("game_tag");

	if (foundName != std::string::npos && foundTag != std::string::npos)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		system("cls");
		if (reader.parse(request, root)) {
			const Json::Value& participants = root["participants"];

			for (const Json::Value& participant : participants) {
				if (participant.isMember("game_name") && participant.isMember("game_tag")) {
					std::string game_name = participant["game_name"].asString();
					std::string game_tag = participant["game_tag"].asString();
					std::string full_name = game_name + "#" + game_tag;
					fullNames.push_back(full_name);
				}
			}
		}

		std::string result;

		std::cout << "Players in champion select:" << std::endl;
		for (const std::string& usernamewithtag : fullNames) {
			std::cout << usernamewithtag << std::endl;
		}
	}
}

void DoStuff()
{
	Json::Value root;
	Json::Reader reader;

	size_t foundPhase = GetSession().find("phase");

	if (foundPhase != std::string::npos)
	{
		if (reader.parse(GetSession(), root))
		{
			std::string phase = root["phase"].asString();

			if (phase == "Lobby")
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
				system("cls");
				std::cout << "Waiting for matchmaking";
			}
			else if (phase == "Matchmaking")
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
				system("cls");
				std::cout << "Waiting for match";
			}
			else if (phase == "ReadyCheck")
			{
				PostAccept();
				system("cls");
				std::cout << "Match accepted";
			}
			else if (phase == "ChampSelect")
			{
				GetPlayerNames(GetParticipants());
			}
			else
			{
				system("pause");
			}
		}
	}
	else
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		system("cls");
		std::cout << "Waiting for lobby";
	}
}

void main(int argc, char* argv[])
{
	system("title lithellx");
	std::cout << "Loading...";

	while (true)
	{
		if (FindWindowA(0, "League of Legends"))
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(500));

			GetRiotClientInfo();
			GetLeagueClientInfo();
			DoStuff();
		}
		else
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			system("cls");
			std::cout << "Waiting for League of Legends";
		}
	}
}