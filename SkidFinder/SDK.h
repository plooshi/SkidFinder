#pragma once
#include "pch.h"

auto ImageBase = *(void**)(__readgsqword(0x60) + 0x10);

class FMemory {
private:
	static inline auto InternalRealloc = ([]() {
		return (void* (*)(void*, __int64, unsigned int)) Memcury::Scanner::FindPattern("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?").Get();
		})();

public:
	template <typename _Dt = uint8>
	static _Dt* Malloc(int32 Count, int32 Alignment = alignof(_Dt)) {
		return (_Dt*)InternalRealloc(nullptr, Count * sizeof(_Dt), Alignment);
	}

	template <typename _Dt = uint8>
	static _Dt* Realloc(_Dt* Ptr, int32 Count, int32 Alignment = alignof(_Dt)) {
		return (_Dt*)InternalRealloc(Ptr, Count * sizeof(_Dt), Alignment);
	}

	static void Free(void* Ptr) {
		InternalRealloc(Ptr, 0, 0);
	}
};

template <typename _Et>
class TArray {
protected:
	_Et* Data;
	int32 NumElements;
	int32 MaxElements;

private:
	inline int32 GetSlack() const { return MaxElements - NumElements; }

	inline void VerifyIndex(int32 Index) const { if (!IsValidIndex(Index)) throw out_of_range("Index was out of range!"); }

	inline       _Et& GetUnsafe(int32 Index) { return Data[Index]; }
	inline const _Et& GetUnsafe(int32 Index) const { return Data[Index]; }


public:
	TArray() : Data(nullptr), NumElements(0), MaxElements(0)
	{
	}

	inline TArray(int32 Size) : NumElements(0), MaxElements(Size), Data(FMemory::Malloc<_Et>(Size))
	{
	}

	inline void Reserve(const int Num)
	{
		if (Num > GetSlack()) Data = FMemory::Realloc<_Et>(Data, MaxElements = Num + NumElements);
	}

	inline _Et& Add(const _Et& Element)
	{
		Reserve(1);

		auto& Elem = Data[NumElements] = Element;
		NumElements++;

		return Elem;
	}

	inline bool Remove(int32 Index)
	{
		if (!IsValidIndex(Index))
			return false;

		NumElements--;

		for (int i = Index; i < NumElements; i++)
		{
			Data[i] = Data[i + 1];
		}

		return true;
	}

	inline void Free()
	{
		if (Data)
			FMemory::Free(Data);

		MaxElements = 0;
		NumElements = 0;
		Data = nullptr;
	}

	inline void ResetNum() {
		NumElements = 0;
	}

	inline void Clear()
	{
		ResetNum();

		if (Data) __stosb((PBYTE)Data, 0, NumElements * sizeof(_Et));
	}

public:
	inline int32 Num() const { return NumElements; }
	inline int32 Max() const { return MaxElements; }

	inline bool IsValidIndex(int32 Index) const { return Data && Index >= 0 && Index < NumElements; }

	inline bool IsValid() const { return Data && NumElements > 0 && MaxElements >= NumElements; }

	_Et* Search(function<bool(_Et& val)> check) {
		for (auto& v : *this) {
			if (check(v)) return &v;
		}
		return nullptr;
	}


	int32_t SearchIndex(function<bool(_Et& val)> check) {
		for (int32_t i = 0; i < Num(); i++) {
			if (check((*this)[i])) return i;
		}
		return -1;
	}

public:
	inline       _Et& operator[](int32 Index) { VerifyIndex(Index); return Data[Index]; }
	inline const _Et& operator[](int32 Index) const { VerifyIndex(Index); return Data[Index]; }


	inline const _Et* GetPtr(int32 Index, int32 Size) const { VerifyIndex(Index); return (_Et*)(__int64(Data) + (Index * Size)); }
	inline const _Et& Get(int32 Index, int32 Size) const { VerifyIndex(Index); return *GetPtr(Index, Size); }

	inline explicit operator bool() const { return IsValid(); };

public:
	inline _Et* begin() { return Data; }
	inline _Et* end() { return Data + Num(); }
};

class FString : public TArray<wchar_t> {
public:
	using TArray::TArray;

	FString(const wchar_t* Str)
	{
		const uint32 Len = static_cast<uint32>(wcslen(Str) + 0x1);

		Data = const_cast<wchar_t*>(Str);
		MaxElements = NumElements = Len;
	}

public:
	inline string ToString() const
	{
		if (*this)
		{
			wstring _Wd(Data);
#pragma warning(suppress: 4244)
			return string(_Wd.begin(), _Wd.end());
		}

		return "";
	}

public:
	inline       wchar_t* c_str() { return Data; }
	inline const wchar_t* c_str() const { return Data; }

public:
	inline bool operator==(const FString& Other) const { return Other && NumElements == Other.NumElements ? wcscmp(Data, Other.Data) == 0 : false; }
	inline bool operator!=(const FString& Other) const { return Other && NumElements != Other.NumElements ? wcscmp(Data, Other.Data) != 0 : true; }
};

class FName {
public:
	int32 ComparisonIndex;
	int32 Number;
	static inline void(*AppendString)(const FName*, FString&) = ([]() {
		auto SRef = Memcury::Scanner::FindStringRef("ForwardShadingQuality_");
		constexpr array<const char*, 5> sigs =
		{
			"48 8D ? ? 48 8D ? ? E8",
			"48 8D ? ? ? 48 8D ? ? E8",
			"48 8D ? ? 49 8B ? E8",
			"48 8D ? ? ? 49 8B ? E8",
			"48 8D ? ? 48 8B ? E8"
		};

		for (auto& sig : sigs) {
			auto Scanner = SRef.ScanFor(sig);
			if (Scanner.Get()) {
				auto pb = Memcury::ASM::pattern2bytes(sig);
				return (void(*)(const FName*, FString&)) Scanner.RelativeOffset((uint32_t)pb.size()).Get();
			}
		}
		return (void(*)(const FName*, FString&)) nullptr;
		})();

	string ToString() const
	{
		thread_local FString TempString(1024);

		AppendString(this, TempString);

		string OutputString = TempString.ToString();
		TempString.Clear();

		return OutputString;
	}

	string ToSDKString() const
	{
		std::string OutputString = ToString();

		size_t pos = OutputString.rfind('/');

		if (pos == std::string::npos)
			return OutputString;

		return OutputString.substr(pos + 1);
	}
};


double FNVer = ([]() {
	auto FNBuild = Memcury::Scanner::FindPattern("2b 00 2b 00 46 00 6f 00 72 00 74 00 6e 00 69 00 74 00 65 00 2b 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 2d 00").Get();
	auto VStart = wcschr((wchar_t*)FNBuild, '-') + 1;
	auto VEnd = wcschr(VStart, '-');
	if (!VEnd) VEnd = (wchar_t*)FNBuild + wcslen((wchar_t*)FNBuild);
	auto sz = (VEnd - VStart);
	wchar_t* s = (wchar_t*)malloc(sz * 2 + 2);
	__movsb((PBYTE)s, (const PBYTE)VStart, sz * 2);
	s[sz] = 0;
	wchar_t* e;
	auto ret = wcstod(s, &e);
	free(s);
	return ret;
	})();

int Chapter = ([]() {
	if (FNVer >= 28.00) return 5;
	if (FNVer == 27.00) return 1; // does c4sog use athena?
	if (FNVer >= 23.00) return 4;
	if (FNVer >= 19.00) return 3;
	if (FNVer >= 11.00) return 2;
	return 1;
	})();


template <typename _Ot>
_Ot& GetFromOffset(void* Obj, uint32 Offset) {
	return *(_Ot*)(__int64(Obj) + Offset);
}

template <typename _Ot>
_Ot& GetFromOffset(const void* Obj, uint32 Offset) {
	return *(_Ot*)(__int64(Obj) + Offset);
}

template <typename _Ot>
_Ot* GetPtrFromOffset(const void* Obj, uint32 Offset) {
	return (_Ot*)(__int64(Obj) + Offset);
}


template<int32 _Sl>
struct DefaultObjChars
{
	char _Ch[_Sl + 9];

	consteval DefaultObjChars(const char(&_St)[_Sl])
	{
		copy_n("Default__", 9, _Ch);
		copy_n(_St, _Sl, _Ch + 9);
	}

	operator const char* () const
	{
		return static_cast<const char*>(_Ch);
	}
};
template<int32 _Sl>
struct ConstexprString
{
	char _Ch[_Sl];

	consteval ConstexprString(const char(&_St)[_Sl])
	{
		copy_n(_St, _Sl, _Ch);
	}

	operator const char* () const
	{
		return static_cast<const char*>(_Ch);
	}
};

class ParamPair {
public:
	std::string _Fi;
	void* _Sc;

	template <typename _Vt>
	ParamPair(std::string _Nm, _Vt _Va) {
		_Fi = _Nm;
		// really scuffed way to make this work, just using & gives the same address for each param
		_Sc = FMemory::Malloc(sizeof(_Vt));
		memcpy(_Sc, &_Va, sizeof(_Vt));
	}
};

class UObject {
public:
	void** Vft;
	int32 ObjectFlags;
	int32 Index;
	class UClass* Class;
	class FName Name;
	UObject* Outer;
	static inline void(*ProcessEventInternal)(const UObject*, class UFunction*, void*) = ([]() {
		uintptr_t addr;
		if (FNVer < 14.00) addr = Memcury::Scanner::FindStringRef(L"AccessNoneNoContext").ScanFor({ 0x40, 0x55 }, true, 0, 1, 2000).Get();
		else addr = Memcury::Scanner::FindStringRef(L"UMeshNetworkComponent::ProcessEvent: Invalid mesh network node type: %s", true, 0, FNVer >= 19.00).ScanFor({ 0xE8 }, true, FNVer < 19.00 ? 1 : 3, 0, 2000).RelativeOffset(1).Get();
		return (void(*)(const UObject*, class UFunction*, void*)) addr;
		})();

public:
	const class UField* GetProperty(const char* Name) const;
	uint32 GetOffset(const char* Name) const {
		static auto OffsetOff = FNVer >= 12.10 && FNVer < 20 ? 0x4c : 0x44;
		auto Prop = GetProperty(Name);
		if (!Prop) return -1;
		return GetFromOffset<uint32>(Prop, OffsetOff);
	}

	template <ConstexprString Name, typename T = UObject*>
	T& Get() const {
		static auto Off = GetOffset(Name);
		if (Off == -1) {
			printf("Failed to get offset for %s!\n", Name._Ch);
			while (true);
		}
		return GetFromOffset<T>(this, Off);
	}

	template <ConstexprString Name>
	void SetBitfield(bool Value) const {
		static auto OffsetOff = FNVer >= 12.10 && FNVer < 20 ? 0x4c : 0x44;
		static auto Prop = GetProperty(Name);
		uint8& Field = GetFromOffset<uint8>(Prop, OffsetOff);
		if (Value) {
			Field |= Prop->GetFieldMask();
		}
		else {
			Field &= ~Prop->GetFieldMask();
		}
	}

	template <ConstexprString Name>
	bool Has() const {
		return GetOffset(Name) != -1;
	}

	template <ConstexprString Name, typename T = UObject*>
	T* GetPtr() const {
		static auto Off = GetOffset(Name);
		if (Off == -1) return nullptr;
		return GetPtrFromOffset<T>(this, Off);
	}

	bool IsA(class UClass* Clss) const {
		static auto SuperOff = FNVer >= 7 ? 0x40 : 0x30;
		for (auto _Cl = Class; _Cl; _Cl = GetFromOffset<UClass*>(_Cl, SuperOff)) {
			if (_Cl == Clss) return true;
		}
		return false;
	}

	class UFunction* GetFunction(const char* Name) const {
		return (UFunction*)GetProperty(Name);
	}

	void ProcessEvent(class UFunction* Function, void* Params) const {
		ProcessEventInternal(this, Function, Params);
	}

	template <ConstexprString Name>
	void Call(void* Params = nullptr) const {
		static auto Function = GetFunction(Name);
		ProcessEvent(Function, Params);
	}

	template <ConstexprString Name>
	void Call(std::vector<ParamPair> Params) const;
};

class UField : public UObject {
public:
	const UField* GetNext(bool bNewFields = false) const {
		auto NextOff = bNewFields ? 0x20 : 0x28;
		return GetFromOffset<UField*>(this, NextOff);
	}


	FName& GetName(bool bNewFields = false) const {
		auto NameOff = bNewFields ? 0x28 : 0x18;
		return GetFromOffset<FName>(this, NameOff);
	}

	const uint8 GetFieldMask() const {
		static auto FieldMaskOff = FNVer >= 12.21 && FNVer < 20 ? 0x7b : 0x73;
		return GetFromOffset<uint8>(this, FieldMaskOff);
	}
};

class UStruct : public UField {
public:
	const UStruct* GetSuper() const {
		static auto SuperOff = FNVer >= 7 ? 0x40 : 0x30;
		return GetFromOffset<UStruct*>(this, SuperOff);
	}
	const int32 GetPropertiesSize() const {
		auto ChildrenOff = FNVer >= 12.10 ? 0x58 : (FNVer >= 7 ? 0x50 : 0x40);
		return GetFromOffset<int32>(this, ChildrenOff);
	}

	const UField* GetChildren(bool bNewFields = false) const {
		auto ChildrenOff = bNewFields ? 0x50 : (FNVer >= 7 ? 0x48 : 0x38);
		return GetFromOffset<UField*>(this, ChildrenOff);
	}
};

class UClass : public UStruct {
public:
	const UField* GetProperty(const char* Name) const {
		for (const UClass* _Cl = this; _Cl; _Cl = (const UClass*)_Cl->GetSuper()) {
			if (FNVer >= 12.10) {
				for (const UField* _Pr = _Cl->GetChildren(true); _Pr; _Pr = _Pr->GetNext(true)) {
					if (_Pr->GetName(true).ToSDKString() == Name) return _Pr;
				}
			}
			for (const UField* _Pr = _Cl->GetChildren(false); _Pr; _Pr = _Pr->GetNext(false)) {
				if (_Pr->GetName(false).ToSDKString() == Name) return _Pr;
			}
		}
		return nullptr;
	}
};


const UField* UObject::GetProperty(const char* Name) const {
	return Class->GetProperty(Name);
}

class UFunction : public UStruct {
public:
	void Call(const UObject* obj, void* Params) {
		if (this) obj->ProcessEvent(this, Params);
	}

	void Call(const UObject* obj, std::vector<ParamPair> Params) {
		if (this) obj->ProcessEvent(this, CreateParams(Params));
	}

	void operator()(const UObject* obj, void* Params) {
		return Call(obj, Params);
	}

	void* GetNativeFunc() {
		if (FNVer <= 6.31) return GetFromOffset<void*>(this, 0xB0);
		else if (FNVer > 7.00 && FNVer < 12.00) return GetFromOffset<void*>(this, 0xC0);
		else if (FNVer >= 12.00 && FNVer < 12.10) return GetFromOffset<void*>(this, 0xC8);
		else if (FNVer >= 12.10 && FNVer <= 12.61) return GetFromOffset<void*>(this, 0xF0);
		else return GetFromOffset<void*>(this, 0xD8);
	}

	int32 GetVTableIndex() {
		if (!this) return -1;
		auto ValidateName = Name.ToString() + "_Validate";
		auto ValidateRef = Memcury::Scanner::FindStringRef(std::wstring(ValidateName.begin(), ValidateName.end()).c_str(), false);

		auto Addr = ValidateRef.Get();

		if (!Addr) {
			Addr = __int64(GetNativeFunc());
		}

		if (Addr) {
			for (int i = 0; i < 2000; i++) {
				if (*((uint8*)Addr + i) == 0xFF && (*((uint8*)Addr + i + 1) == 0x90 || *((uint8*)Addr + i + 1) == 0x93 || *((uint8*)Addr + i + 1) == 0xA0)) {
					auto VTIndex = *(uint32_t*)(Addr + i + 2);

					return VTIndex / 8;
				}
			}
		}
		return -1;
	}

	struct Param {
		std::string Name;
		uint32 Offset;
	};
	class Params {
	public:
		std::vector<Param> NameOffsetMap;
		uint32 Size;
	};

	Params GetParams() {
		Params p;
		static auto OffsetOff = FNVer >= 12.10 && FNVer < 20 ? 0x4c : 0x44;

		if (FNVer >= 12.10) {
			for (const UField* _Pr = GetChildren(true); _Pr; _Pr = _Pr->GetNext(true)) {
				p.NameOffsetMap.push_back({ _Pr->GetName(true).ToSDKString(), GetFromOffset<uint32>(_Pr, OffsetOff) });
			}
		}
		for (const UField* _Pr = GetChildren(false); _Pr; _Pr = _Pr->GetNext(false)) {
			p.NameOffsetMap.push_back({ _Pr->GetName(false).ToSDKString(), GetFromOffset<uint32>(_Pr, OffsetOff) });
		}

		p.Size = GetPropertiesSize();
		return p;
	}

	void* CreateParams(std::vector<ParamPair> InputParams) {
		auto Mem = FMemory::Malloc(GetParams().Size);
		auto Params = GetParams();

		for (auto& _Pa : InputParams) {
			Param FoundParam;
			int i = 0;
			uint32 Size = 0;
			for (auto& _Mp : Params.NameOffsetMap) {
				if (_Mp.Name == _Pa._Fi) {
					FoundParam = _Mp;
					Size = i == Params.NameOffsetMap.size() - 1 ? Params.Size - _Mp.Offset : Params.NameOffsetMap[i + 1].Offset - _Mp.Offset;
					break;
				}
				i++;
			}

			if (Size) {
				memcpy((PBYTE)Mem + FoundParam.Offset, _Pa._Sc, Size);
			}
		}
		return Mem;
	}

	template <typename _Rt>
	_Rt* GetValueFromParams(void* Params, const char* Name) {
		auto Params = GetParams();

		for (auto& _Mp : Params.NameOffsetMap) {
			if (_Mp.Name == Name) {
				return GetPtrFromOffset<_Rt>(Params, _Mp.Offset);
			}
		}

		return nullptr;
	}
};

template <ConstexprString Name>
void UObject::Call(std::vector<ParamPair> Params) const {
	static auto Function = GetFunction(Name);
	ProcessEvent(Function, Function->CreateParams(Params));
}

struct FUObjectItem final
{
public:
	class UObject* Object;
	int32 Flags;
	int32 ClusterRootIndex;
	int32 SerialNumber;
};

class TUObjectArrayUnchunked
{
private:
	const FUObjectItem* Objects;
	const int32 MaxElements;
	const int32 NumElements;

public:
	inline int Num() const
	{
		return NumElements;
	}

	inline int Max() const
	{
		return MaxElements;
	}

	inline const FUObjectItem* GetItemByIndex(const int32 Index) const
	{
		if (Index < 0 || Index > NumElements)
			return nullptr;

		return Objects + Index;
	}
};

class TUObjectArrayChunked
{
private:
	const FUObjectItem** Objects;
	const FUObjectItem* PreAllocatedObjects;
	const int32 MaxElements;
	const int32 NumElements;
	const int32 MaxChunks;
	const int32 NumChunks;

public:
	inline int Num() const
	{
		return NumElements;
	}

	inline int Max() const
	{
		return MaxElements;
	}

	inline const FUObjectItem* GetItemByIndex(const int32 Index) const
	{
		if (Index < 0 || Index > NumElements)
			return nullptr;

		const int32 ChunkIndex = Index / 0x10000;
		const int32 ChunkOffset = Index % 0x10000;

		return Objects[ChunkIndex] + ChunkOffset;
	}
};

class TUObjectArray {
public:
	static inline TUObjectArrayChunked* GObjectsChunked = ([]() {
		if (FNVer >= 5.00) {
			return (TUObjectArrayChunked*)Memcury::Scanner::FindPattern(FNVer <= 6.02 ? "48 8B 05 ? ? ? ? 48 8B 0C C8 48 8D 04 D1" : "48 8B 05 ? ? ? ? 48 8B 0C C8 48 8B 04 D1").RelativeOffset(3).Get();
		}
		return (TUObjectArrayChunked*)nullptr;
		})();
	static inline TUObjectArrayUnchunked* GObjectsUnchunked = ([]() {
		if (FNVer < 5.00) {
			auto Addr = Memcury::Scanner::FindPattern("48 8B 05 ? ? ? ? 48 8D 14 C8 EB 03 49 8B D6 8B 42 08 C1 E8 1D A8 01 0F 85 ? ? ? ? F7 86 ? ? ? ? ? ? ? ?", false);
			if (!Addr.Get()) {
				Addr = Memcury::Scanner::FindPattern("48 8B 05 ? ? ? ? 48 8D 1C C8 81 4B ? ? ? ? ? 49 63 76 30", false);
			}
			return (TUObjectArrayUnchunked*)Addr.RelativeOffset(3).Get();
		}
		return (TUObjectArrayUnchunked*)nullptr;
		})();
public:
	static const int32 Num() {
		return GObjectsChunked ? GObjectsChunked->Num() : GObjectsUnchunked->Num();
	}

	static const int32 Max() {
		return GObjectsChunked ? GObjectsChunked->Max() : GObjectsUnchunked->Max();
	}

	static const FUObjectItem* GetItemByIndex(const int32 Index) {
		return GObjectsChunked ? GObjectsChunked->GetItemByIndex(Index) : GObjectsUnchunked->GetItemByIndex(Index);
	}

	static const UObject* GetObjectByIndex(const int32 Index) {
		const FUObjectItem* Item = GetItemByIndex(Index);
		return Item ? Item->Object : nullptr;
	}

	static const UObject* FindObject(const char* Name) {
		for (int i = 0; i < Num(); i++) {
			const UObject* Obj = GetObjectByIndex(i);
			if (Obj && Obj->Name.ToString() == Name)
				return Obj;
		}
		return nullptr;
	}

	template <typename _Et = UObject>
	static const _Et* FindObject(const char* Name) {
		return (const _Et*)FindObject(Name);
	}

	template <typename _Et = UObject>
	static const _Et* FindObject(const std::string& Name) {
		return FindObject<_Et>(Name.c_str());
	}

	static const UObject* FindFirstObject(const char* Name) {
		UClass* TargetClass = (UClass*)FindObject(Name);
		for (int i = 0; i < Num(); i++) {
			const UObject* Obj = GetObjectByIndex(i);
			if (Obj && !(Obj->ObjectFlags & 16) && Obj->IsA(TargetClass))
				return Obj;
		}
		return nullptr;
	}
};

template <typename T = UObject*, typename _St>
T& StructGet(_St*& StructInstance, const char* StructName, const char* Name) {
	auto Struct = TUObjectArray::FindObject<UClass>(StructName);

	static auto OffsetOff = FNVer >= 12.10 && FNVer < 20 ? 0x4c : 0x44;
	auto Off = GetFromOffset<uint32>(Struct->GetProperty(Name), OffsetOff);
	return GetFromOffset<T>(StructInstance, Off);
}

template <DefaultObjChars Name>
const UObject* GetDefaultObj() {
	static auto Obj = TUObjectArray::FindObject(Name);
	return Obj;
}

class WrapperBase {
private:
	virtual const UObject* Get() const = 0;

public:
	operator const UObject* () const {
		return Get();
	}

	operator UObject* () const {
		return (UObject*)Get();
	}

	const UObject* operator->() const {
		return Get();
	}

	operator bool() const {
		return Get() != nullptr;
	}
};

class EngineWrapper : public WrapperBase {
public:
	const UObject* Get() const {
		return TUObjectArray::FindFirstObject("FortEngine");
	}
};

EngineWrapper Engine;

class WorldWrapper : public WrapperBase {
public:
	const UObject* Get() const {
		return Engine->Get<"GameViewport">()->Get<"World">();
	}
};

WorldWrapper World;

class GameModeWrapper : public WrapperBase {
public:
	const UObject* Get() const {
		return World->Get<"AuthorityGameMode">();
	}
};

GameModeWrapper GameMode;

class GameStateWrapper : public WrapperBase {
public:
	const UObject* Get() const {
		return World->Get<"GameState">();
	}
};

GameStateWrapper GameState;

void* nullptrForHook;

template<DefaultObjChars ClassName, typename T = void*>
__forceinline void Hook(int idx, void* detour, T& og = nullptrForHook) {
	auto VTable = (void**)GetDefaultObj<ClassName>()->Vft;
	if (!is_same_v<T, void*>)
		og = (T)VTable[idx];

	DWORD vpog;
	VirtualProtect(VTable + idx, 8, PAGE_EXECUTE_READWRITE, &vpog);
	VTable[idx] = detour;
	VirtualProtect(VTable + idx, 8, vpog, &vpog);
}


template<DefaultObjChars ClassName, ConstexprString FuncName, typename T = void*>
__forceinline void Hook(void* detour, T& og = nullptrForHook) {
	auto DefaultObj = GetDefaultObj<ClassName>();
	auto VTable = (void**)DefaultObj->Vft;
	int idx = DefaultObj->GetFunction(FuncName)->GetVTableIndex();
	if (!is_same_v<T, void*>)
		og = (T)VTable[idx];

	DWORD vpog;
	VirtualProtect(VTable + idx, 8, PAGE_EXECUTE_READWRITE, &vpog);
	VTable[idx] = detour;
	VirtualProtect(VTable + idx, 8, vpog, &vpog);
}


#include "MinHook.h"

template<typename T = void*>
__forceinline void Hook(uintptr_t base, void* detour, T& og = nullptrForHook) {
	MH_CreateHook(LPVOID(base), detour, is_same_v<T, void*> ? nullptr : (LPVOID*)&og);
}

struct FFastArraySerializerItem
{
public:
	int32 ReplicationID;
	int32 ReplicationKey;
	int32 MostRecentArrayReplicationKey;
};

struct alignas(0x08) FFastArraySerializer
{
public:
	char ItemMap[0x50];
	int32 IDCounter;
	int32 ArrayReplicationKey;
	char GuidReferencesMap[0x50];

	int32& GetCachedItems() {
		return GetFromOffset<int32>(this, FNVer >= 8.30 ? 0xf8 : 0xa8);
	}

	int32& GetCachedItemsToConsiderForWriting() {
		return GetFromOffset<int32>(this, FNVer >= 8.30 ? 0xfc : 0xac);
	}

	/** This must be called if you add or change an item in the array */
	void MarkItemDirty(FFastArraySerializerItem& Item)
	{
		if (Item.ReplicationID == -1)
		{
			Item.ReplicationID = ++IDCounter;
			if (IDCounter == -1)
			{
				IDCounter++;
			}
		}

		Item.ReplicationKey++;
		MarkArrayDirty();
	}

	/** This must be called if you just remove something from the array */
	void MarkArrayDirty()
	{
		// ItemMap.Reset();        // This allows to clients to add predictive elements to arrays without affecting replication.
		IncrementArrayReplicationKey();

		// Invalidate the cached item counts so that they're recomputed during the next write
		GetCachedItems() = -1;
		GetCachedItemsToConsiderForWriting() = -1;
	}

	void IncrementArrayReplicationKey()
	{
		ArrayReplicationKey++;
		if (ArrayReplicationKey == -1)
		{
			ArrayReplicationKey++;
		}
	}
};

class AActor : public UObject {};

template<typename _Ct>
class TSubclassOf
{
	const UClass* ClassPtr;

public:
	TSubclassOf() = default;

	inline TSubclassOf(const UClass* Class)
		: ClassPtr(Class)
	{
	}

	inline UClass* Get()
	{
		return ClassPtr;
	}

	inline operator UClass* () const
	{
		return ClassPtr;
	}

	template<typename Target, typename = std::enable_if<std::is_base_of_v<Target, _Ct>, bool>::type>
	inline operator TSubclassOf<Target>() const
	{
		return ClassPtr;
	}

	inline UClass* operator->()
	{
		return ClassPtr;
	}

	inline TSubclassOf& operator=(UClass* Class)
	{
		ClassPtr = Class;

		return *this;
	}

	inline bool operator==(const TSubclassOf& Other) const
	{
		return ClassPtr == Other.ClassPtr;
	}

	inline bool operator!=(const TSubclassOf& Other) const
	{
		return ClassPtr != Other.ClassPtr;
	}

	inline bool operator==(UClass* Other) const
	{
		return ClassPtr == Other;
	}

	inline bool operator!=(UClass* Other) const
	{
		return ClassPtr != Other;
	}
};

struct GameplayStatics_GetAllActorsOfClass final
{
public:
	const class UObject* WorldContextObject;
	TSubclassOf<class AActor> ActorClass;
	TArray<class AActor*> OutActors;
};


static TArray<AActor*> GetAll(const UClass* Class) {
	GameplayStatics_GetAllActorsOfClass Params{ World, Class };
	GetDefaultObj<"GameplayStatics">()->Call<"GetAllActorsOfClass">(&Params);
	return Params.OutActors;
}

template <ConstexprString Str>
static TArray<AActor*> GetAll() {
	static auto Class = TUObjectArray::FindObject<UClass>(Str); // we can do this because of the template
	return GetAll(Class);
}

struct FVector
{
public:
	using UnderlayingType = float;                                                                   // 0x0000(0x0008)(NOT AUTO-GENERATED PROPERTY)

	float X;
	float Y;
	float Z;

public:
	FVector& Normalize()
	{
		*this /= Magnitude();
		return *this;
	}
	FVector& operator*=(const FVector& Other)
	{
		*this = *this * Other;
		return *this;
	}
	FVector& operator*=(float Scalar)
	{
		*this = *this * Scalar;
		return *this;
	}
	FVector& operator+=(const FVector& Other)
	{
		*this = *this + Other;
		return *this;
	}
	FVector& operator-=(const FVector& Other)
	{
		*this = *this - Other;
		return *this;
	}
	FVector& operator/=(const FVector& Other)
	{
		*this = *this / Other;
		return *this;
	}
	FVector& operator/=(float Scalar)
	{
		*this = *this / Scalar;
		return *this;
	}

	UnderlayingType Dot(const FVector& Other) const
	{
		return (X * Other.X) + (Y * Other.Y) + (Z * Other.Z);
	}
	UnderlayingType GetDistanceTo(const FVector& Other) const
	{
		FVector DiffVector = Other - *this;
		return DiffVector.Magnitude();
	}
	UnderlayingType GetDistanceToInMeters(const FVector& Other) const
	{
		return GetDistanceTo(Other) * 0.01f;
	}
	FVector GetNormalized() const
	{
		return *this / Magnitude();
	}
	bool IsZero() const
	{
		return X == 0.0 && Y == 0.0 && Z == 0.0;
	}
	UnderlayingType Magnitude() const
	{
		return std::sqrt((X * X) + (Y * Y) + (Z * Z));
	}
	bool operator!=(const FVector& Other) const
	{
		return X != Other.X || Y != Other.Y || Z != Other.Z;
	}
	FVector operator*(const FVector& Other) const
	{
		return { X * Other.X, Y * Other.Y, Z * Other.Z };
	}
	FVector operator*(float Scalar) const
	{
		return { X * Scalar, Y * Scalar, Z * Scalar };
	}
	FVector operator+(const FVector& Other) const
	{
		return { X + Other.X, Y + Other.Y, Z + Other.Z };
	}
	FVector operator-(const FVector& Other) const
	{
		return { X - Other.X, Y - Other.Y, Z - Other.Z };
	}
	FVector operator/(const FVector& Other) const
	{
		if (Other.X == 0.0f || Other.Y == 0.0f || Other.Z == 0.0f)
			return *this;

		return { X / Other.X, Y / Other.Y, Z / Other.Z };
	}
	FVector operator/(float Scalar) const
	{
		if (Scalar == 0.0f)
			return *this;

		return { X / Scalar, Y / Scalar, Z / Scalar };
	}
	bool operator==(const FVector& Other) const
	{
		return X == Other.X && Y == Other.Y && Z == Other.Z;
	}
};

struct alignas(0x10) FQuat
{
public:
	float X;
	float Y;
	float Z;
	float W;
};

struct FRotator final
{
public:
	float Pitch;
	float Yaw;
	float Roll;

	operator FQuat() {
		float halfOfARadian = 0.008726646259971648f;
		float sinPitch = sin(Pitch * halfOfARadian),
			sinYaw = sin(Yaw * halfOfARadian),
			sinRoll = sin(Roll * halfOfARadian);
		float cosPitch = cos(Pitch * halfOfARadian),
			cosYaw = cos(Yaw * halfOfARadian),
			cosRoll = cos(Roll * halfOfARadian);

		FQuat out{};
		out.X = cosRoll * sinPitch * sinYaw - sinRoll * cosPitch * cosYaw;
		out.Y = -cosRoll * sinPitch * cosYaw - sinRoll * cosPitch * sinYaw;
		out.Z = cosRoll * cosPitch * sinYaw - sinRoll * sinPitch * cosYaw;
		out.W = cosRoll * cosPitch * cosYaw + sinRoll * sinPitch * sinYaw;
		return out;
	}

	operator FVector()
	{
		float oneRadian = 0.017453292519943295f;
		float cosPitch = cos(Pitch * oneRadian), cosYaw = cos(Yaw * oneRadian);
		float sinPitch = sin(Pitch * oneRadian), sinYaw = sin(Yaw * oneRadian);

		return FVector(cosPitch * cosYaw, cosPitch * sinYaw, sinPitch);
	}
};

struct FTransform
{
public:
	struct FQuat Rotation;
	struct FVector Translation;
	uint8 _Padding1[0x4];
	struct FVector Scale3D;
	uint8 _Padding2[0x4];

	FTransform() {}
	FTransform(FVector loc, FQuat rot, FVector scale = { 1, 1, 1 }) : Translation(loc), Rotation(rot), Scale3D(scale) {}
};

struct GameplayStatics_BeginDeferredActorSpawnFromClass
{
public:
	const class UObject* WorldContextObject;
	TSubclassOf<class AActor> ActorClass;
	struct FTransform SpawnTransform;
	uint8 CollisionHandlingOverride;
	uint8 _Padding1[0x7];
	class AActor* Owner;
	class AActor* ReturnValue;
	uint8 _Padding2[0x8];
};

struct GameplayStatics_FinishSpawningActor
{
public:
	class AActor* Actor;
	uint8 _Padding1[0x8];
	struct FTransform SpawnTransform;
	class AActor* ReturnValue;
	uint8 _Padding2[0x8];
};

AActor* SpawnActor(const UClass* Class, FVector Loc, FRotator Rot = {}, AActor* Owner = nullptr)
{
	FTransform Transform(Loc, Rot);

	auto Statics = GetDefaultObj<"GameplayStatics">();
	GameplayStatics_BeginDeferredActorSpawnFromClass Params;
	Params.WorldContextObject = World;
	Params.ActorClass = Class;
	Params.SpawnTransform = Transform;
	Params.CollisionHandlingOverride = 2; // AdjustIfPossibleButAlwaysSpawn
	Params.Owner = Owner;
	Statics->Call<"BeginDeferredActorSpawnFromClass">(&Params);

	GameplayStatics_FinishSpawningActor Params2;
	Params2.Actor = Params.ReturnValue;
	Params2.SpawnTransform = Transform;
	Statics->Call<"FinishSpawningActor">(&Params2);
	return Params2.ReturnValue;
}

AActor* SpawnActor(const UClass* Class, FTransform Transform, AActor* Owner = nullptr)
{
	auto Statics = GetDefaultObj<"GameplayStatics">();
	GameplayStatics_BeginDeferredActorSpawnFromClass Params;
	Params.WorldContextObject = World;
	Params.ActorClass = Class;
	Params.SpawnTransform = Transform;
	Params.CollisionHandlingOverride = 2; // AdjustIfPossibleButAlwaysSpawn
	Params.Owner = Owner;
	Statics->Call<"BeginDeferredActorSpawnFromClass">(&Params);

	GameplayStatics_FinishSpawningActor Params2;
	Params2.Actor = Params.ReturnValue;
	Params2.SpawnTransform = Transform;
	Statics->Call<"FinishSpawningActor">(&Params2);
	return Params2.ReturnValue;
}

template<typename T = AActor>
T* SpawnActorUnfinished(const UClass* Class, FVector Loc, FRotator Rot = {}, AActor* Owner = nullptr)
{
	FTransform Transform(Loc, Rot);

	auto Statics = GetDefaultObj<"GameplayStatics">();
	GameplayStatics_BeginDeferredActorSpawnFromClass Params;
	Params.WorldContextObject = World;
	Params.ActorClass = Class;
	Params.SpawnTransform = Transform;
	Params.CollisionHandlingOverride = 2; // AdjustIfPossibleButAlwaysSpawn
	Params.Owner = Owner;
	Statics->Call<"BeginDeferredActorSpawnFromClass">(&Params);
	return Params.ReturnValue;
}

template<typename T = AActor>
T* FinishSpawnActor(const AActor* Actor, FVector Loc, FRotator Rot)
{
	FTransform Transform(Loc, Rot);

	auto Statics = GetDefaultObj<"GameplayStatics">();
	GameplayStatics_FinishSpawningActor Params2;
	Params2.Actor = Actor;
	Params2.SpawnTransform = Transform;
	Statics->Call<"FinishSpawningActor">(&Params2);
	return Params2.ReturnValue;
}

struct KismetStringLibrary_Conv_StringToName
{
public:
	class FString InString;
	class FName ReturnValue;
};

FName Conv_StringToName(FString Str) {
	KismetStringLibrary_Conv_StringToName Params{ Str };
	GetDefaultObj<"KismetStringLibrary">()->Call<"Conv_StringToName">(&Params);
	return Params.ReturnValue;
}

struct UScriptStruct {

};

struct FURL
{
public:
	class FString Protocol;
	class FString Host;
	int32 Port;
	uint8 Pad_BC4[0x4];
	class FString Map;
	class FString RedirectUrl;
	TArray<class FString> Op;
	class FString Portal;
	int32 Valid;
	uint8 Pad_BC5[0x4];
};

template<typename ...Args>
void Log(Args && ...args)
{
	cout << "LogFinder: Display: ";
	(cout << ... << args);
	cout << endl;
}

class FWeakObjectPtr
{
public:
	int32 ObjectIndex;
	int32 ObjectSerialNumber;

public:
	const UObject* Get() const {
		return TUObjectArray::GetObjectByIndex(ObjectIndex);
	}
	const UObject* operator->() const {
		return Get();
	}
	bool operator==(const FWeakObjectPtr& Other) const {
		return ObjectIndex == Other.ObjectIndex;
	}
	bool operator!=(const FWeakObjectPtr& Other) const {
		return ObjectIndex != Other.ObjectIndex;
	}
	bool operator==(const class UObject* Other) const {
		return ObjectIndex == Other->Index;
	}
	bool operator!=(const class UObject* Other) const {
		return ObjectIndex != Other->Index;
	}
};

template<typename _Oi>
class TPersistentObjectPtr
{
public:
	FWeakObjectPtr WeakPtr;
	int32 TagAtLastTest;
	_Oi ObjectID;

public:
	class UObject* Get() const
	{
		return WeakPtr.Get();
	}
	class UObject* operator->() const
	{
		return WeakPtr.Get();
	}
};


struct FSoftObjectPath
{
public:
	class FName AssetPathName;
	class FString SubPathString;
};

template<typename _Ut>
class TSoftObjectPtr : public TPersistentObjectPtr<FSoftObjectPath>
{
public:
	_Ut* Get() const
	{
		return static_cast<_Ut*>(TPersistentObjectPtr::Get());
	}
	_Ut* operator->() const
	{
		return static_cast<_Ut*>(TPersistentObjectPtr::Get());
	}
};

template<typename _Ut>
class TSoftClassPtr : public TPersistentObjectPtr<FSoftObjectPath>
{
public:
	_Ut* Get() const
	{
		return static_cast<_Ut*>(TPersistentObjectPtr::Get());
	}
	_Ut* operator->() const
	{
		return static_cast<_Ut*>(TPersistentObjectPtr::Get());
	}
};