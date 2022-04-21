#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <malloc.h>
#include <string>
#include <tuple>


namespace MemoryScanner {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Diagnostics;
	/// <summary>
	/// Summary for PointerScanner
	/// </summary>

	typedef struct _CLIENT_ID
	{
		PVOID UniqueProcess;
		PVOID UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef struct _THREAD_BASIC_INFORMATION
	{
		NTSTATUS                ExitStatus;
		PVOID                   TebBaseAddress;
		CLIENT_ID               ClientId;
		KAFFINITY               AffinityMask;
		DWORD               Priority;
		DWORD               BasePriority;
	} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

	public ref class PointerScanner : public System::Windows::Forms::Form
	{
	public:
		ArrayList arrlist,arrlist1,arrlist2,arrlist3,arrlist4;
	private: System::Windows::Forms::ColumnHeader^  columnHeader3;
	public: 
	private: System::Windows::Forms::ColumnHeader^  columnHeader6;
	public: 
		PointerScanner(void)
		{
			InitializeComponent();
			//
			//TODO: Add the constructor code here
			//
		}


		int PointerScan(HANDLE hProcess ,int PID ,long  ADDRESS,int offsets)
		{
			int counter;
			SYSTEM_INFO sys_inf;
			GetSystemInfo(&sys_inf);
			int Mc = 0;
			int * offset1;
			int * offset2;
			long * address = &ADDRESS;
			long * buffer = ScanMemory(hProcess,address,offsets,&counter,&offset1,1,0,0);
			MODULEENTRY32 * pme32 = msInfo(PID,&Mc);
			long * addressChecked = checker(pme32,Mc,buffer,&counter,&offset1,0,0);
			int c = ModulePointerScan(hProcess,PID,addressChecked,offsets,counter,&Mc,pme32,offset1,0,2,(long)sys_inf.lpMinimumApplicationAddress,(long)sys_inf.lpMaximumApplicationAddress-2047);
			int b =  ModulePointerScan(hProcess,PID,address,offsets,1,&Mc,pme32,0,0,1,(long)sys_inf.lpMinimumApplicationAddress,(long)sys_inf.lpMaximumApplicationAddress);
			long * buffer1 = ScanMemory(hProcess,addressChecked,offsets,&counter,&offset2,counter,&offset1,1);
			int a = ModulePointerScan(hProcess,PID,checker(pme32,Mc,buffer1,&counter,&offset1,&offset2,1),offsets,counter,&Mc,pme32,offset1,offset2,3,(long)sys_inf.lpMinimumApplicationAddress,(long)sys_inf.lpMaximumApplicationAddress-2047);
			free(buffer);
			free(buffer1);
			free(offset1);
			return b+a+c;
			
		}

		int scanThreadStack(int pid,HANDLE pHANDLE,long address,int offset)
		{
			HANDLE threadSnapH = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,pid);
			THREADENTRY32 te32 ;
			long OTP = 0;
			te32.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(threadSnapH,&te32))
			{
				
			}
			return 0;
		}

		int GeneratePointerMap(HANDLE hprocess,int pid,int offset,long address/*,long address,int OFFSET*/)
		{
			int counter1;
			unsigned int * mBuffer;
			unsigned int * mOffSet;
			int * offset1;
			int * offset2;
			long * Address = &address;
			SYSTEM_INFO sys_info;
			GetSystemInfo(&sys_info);
			MEMORY_BASIC_INFORMATION * MEM_BASIC_INFO = (MEMORY_BASIC_INFORMATION*)calloc(1,sizeof(MEMORY_BASIC_INFORMATION));
			int Rc,Mc = 0;
			MemoryRegions(hprocess,&MEM_BASIC_INFO,&Rc);
			MODULEENTRY32 * pme32  = msInfo(pid,&Mc);
			int * counter = PointerGenerator(hprocess,offset,Mc,pme32,MEM_BASIC_INFO,Rc,(long)sys_info.lpMinimumApplicationAddress,(long)sys_info.lpMaximumApplicationAddress,&mBuffer,&mOffSet);
			int a1 = ScanPointerNV(counter,offset,mBuffer,mOffSet,Address,1,Mc,pme32,0,0,1);
			long * BUFFER1 = ScanMemory(hprocess,Address,offset,&counter1,&offset1,1,0,0);
			long * ADDRESSESCHECKED = checker(pme32,Mc,BUFFER1,&counter1,&offset1,0,0);
			int a2 = ScanPointerNV(counter,offset,mBuffer,mOffSet,ADDRESSESCHECKED,counter1,Mc,pme32,offset1,0,2);
			long * BUFFER2 = ScanMemory(hprocess,ADDRESSESCHECKED,offset,&counter1,&offset2,counter1,&offset1,1);
			int a3 = ScanPointerNV(counter,offset,mBuffer,mOffSet,checker(pme32,Mc,BUFFER2,&counter1,&offset1,&offset2,1),counter1,Mc,pme32,offset1,offset2,3);
			return a1+a2+a3;
		}

		void MemoryRegions(HANDLE hProcess,MEMORY_BASIC_INFORMATION ** mem_basic_info,int * counter)
		{
			MEMORY_BASIC_INFORMATION * me_ba_in =(MEMORY_BASIC_INFORMATION*)calloc(1,sizeof(MEMORY_BASIC_INFORMATION));
			unsigned int ** BUFFER = (unsigned int**)malloc(sizeof(unsigned int));
			int Rc = 0;
			SYSTEM_INFO sys_info;
			GetSystemInfo(&sys_info);
			long min_addr = (long)sys_info.lpMinimumApplicationAddress;
			long max_addr = (long)sys_info.lpMaximumApplicationAddress;
			while (min_addr < max_addr)
			{
				MEMORY_BASIC_INFORMATION MBI = {0};
				VirtualQueryEx(hProcess,(void*)min_addr,&MBI,sizeof(MEMORY_BASIC_INFORMATION));
				if (MBI.Protect == PAGE_READWRITE && MBI.State == MEM_COMMIT)
				{
					me_ba_in[Rc] = MBI;
					Rc++;
					me_ba_in =(MEMORY_BASIC_INFORMATION*)realloc(me_ba_in,sizeof(MEMORY_BASIC_INFORMATION)*(Rc+1));
				}
				min_addr +=(long)MBI.RegionSize;
			}
			*mem_basic_info = me_ba_in;
			*counter = Rc;
		}

		long * ScanMemory(HANDLE pHandle,long * address,int offsets,int * counter,int ** offset,int AddressesN,int ** OldOffsets,int scanlvl)
		{
			int c12 = 0;
			long * results =(long*)calloc(2,sizeof(long));
			int * OFFS =(int*)calloc(1,sizeof(int));
			int * OOFFS =(int*)calloc(1,sizeof(int));
			int c = 0;
			SYSTEM_INFO sys_info;
			GetSystemInfo(&sys_info);
			long min_addr =(long)sys_info.lpMinimumApplicationAddress;
			long max_addr =(long)sys_info.lpMaximumApplicationAddress;
			while (min_addr < max_addr)
			{
				MEMORY_BASIC_INFORMATION mem_basic_info = {0};
				VirtualQueryEx(pHandle,(void*)min_addr,&mem_basic_info,sizeof(MEMORY_BASIC_INFORMATION));
				if (mem_basic_info.Protect ==PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
				{
					unsigned int * buffer =(unsigned int*)calloc(mem_basic_info.RegionSize/4+1,sizeof(unsigned int));
					ReadProcessMemory(pHandle,(void*)mem_basic_info.BaseAddress,buffer,(long)mem_basic_info.RegionSize,0);
					for (int i = 0; i < mem_basic_info.RegionSize/4; i++)
					{
						for (int i1 = 0; i1 < AddressesN; i1++)
						{
							if (scanlvl == 1)
							{
								if ((buffer[i]+offsets > address[i1] && buffer[i] < address[i1] && !(buffer[i]%4)))
								{
									results[c] =(long)mem_basic_info.BaseAddress + i*4;
									OFFS[c] = address[i1]-buffer[i];
									OOFFS[c] = OldOffsets[0][i1];
									c++;
									results =(long*)realloc(results,sizeof(long)*(c+1));
									OFFS =(int*)realloc(OFFS,sizeof(int)*(c+1));
									OOFFS =(int*)realloc(OOFFS,sizeof(int)*(c+1));
								}
							}else{
								if ((buffer[i] > address[i1]-offsets && buffer[i] < address[i1] && !(buffer[i]%4)))
								{
									results[c] =(long)mem_basic_info.BaseAddress + i*4;
									OFFS[c] = address[i1]-buffer[i];
									c++;
									results =(long*)realloc(results,sizeof(long)*(c+1));
									OFFS =(int*)realloc(OFFS,sizeof(int)*(c+1));
								}
							}
						}
					}
					c12++;
					free(buffer);
				}
				min_addr += mem_basic_info.RegionSize;
			}
			*offset = OFFS;
			if (scanlvl == 1)
			{
				*OldOffsets = OOFFS;
			}
			counter[0] = c;
			return results;
		}

		MODULEENTRY32 * msInfo(int PID ,int * Mc)
		{
			HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,PID);
			MODULEENTRY32 me32,*pme32;
			pme32 =(MODULEENTRY32*)malloc(sizeof(MODULEENTRY32));
			me32.dwSize = sizeof(MODULEENTRY32);
			if(Module32First(SnapShot,&me32))
			{
				do
				{
					if (me32.th32ProcessID == PID)
					{
						pme32[*Mc] = me32;
						Mc[0]++;
						pme32 = (MODULEENTRY32*)realloc(pme32,sizeof(MODULEENTRY32)*(*Mc+1));
					}
				} while (Module32Next(SnapShot,&me32));
			}
			return pme32;
		}

		long * checker(MODULEENTRY32 * pme32,int mCounter,long * buffer,int * bCounter,int** offset,int ** OldOffset,int type)
		{
			int counter = 0;
			long* nBuffer =(long*)malloc(sizeof(int));
			int* nOffset =(int*)malloc(sizeof(int));
			int* ONOffset =(int*)malloc(sizeof(int));
			for (int i = 0; i < *bCounter; i++)
			{
				int ck = 0;
				for (int i1 = 0; i1 < mCounter; i1++)
				{
					if (buffer[i] > (long)pme32[i1].modBaseAddr && buffer[i] < (long)pme32[i1].modBaseAddr+pme32[i1].modBaseSize)
					{
						ck = 1;
						break;
					}
				}
				if (!ck)
				{
					if (type == 0)
					{
						nBuffer[counter] = buffer[i];
						nOffset[counter] = offset[0][i];
						counter++;
						nBuffer = (long*)realloc(nBuffer,(counter+1)*sizeof(long));
						nOffset = (int*)realloc(nOffset,(counter+1)*sizeof(int));
					}else if(type == 1){
						nBuffer[counter] = buffer[i];
						nOffset[counter] = offset[0][i];
						ONOffset[counter] = OldOffset[0][i];
						counter++;
						nBuffer = (long*)realloc(nBuffer,(counter+1)*sizeof(long));
						nOffset = (int*)realloc(nOffset,(counter+1)*sizeof(int));
						ONOffset = (int*)realloc(ONOffset,(counter+1)*sizeof(int));
					}
				}
			}
			bCounter[0] = counter;
			free(*offset);
			*offset = nOffset;
			if (type == 1)
			{
				*OldOffset = ONOffset;
			}
			return nBuffer;
		}

		int ModulePointerScan(HANDLE hProcess,int PID,long * address,int offsets,int counter,int * Mc,MODULEENTRY32 * pme32,int * offset1,int * offset2,int type,long min_addr1,long max_addr1)
		{
			int coutner = 0;
			for (int i = 0; i < *Mc; i++)
			{
				unsigned int min_addr =(long)pme32[i].modBaseAddr;
				unsigned int max_addr =(long)(pme32[i].modBaseAddr +pme32[i].modBaseSize);
				int ic = 0;
				while (min_addr < max_addr)
				{
					MEMORY_BASIC_INFORMATION mem_basic_info = {0};
					VirtualQueryEx(hProcess,(void*)min_addr,&mem_basic_info,sizeof(MEMORY_BASIC_INFORMATION));
					char str1[8];
					char str2[8] = "Windows";
					WideCharToMultiByte(CP_ACP,0,pme32[i].szExePath+3,7,str1,260,0,0);
					str1[7] = 0;
					if (strcmp(str1,str2) != 0)
					{
						if ((mem_basic_info.Protect ==PAGE_EXECUTE_READ || PAGE_READONLY || PAGE_READWRITE)  /*&& ((long)mem_basic_info.AllocationBase == (long)pme32[i].modBaseAddr)*/)
						{
							unsigned long * buffer =(unsigned long*)malloc(mem_basic_info.RegionSize+1);
							ReadProcessMemory(hProcess,(void*)mem_basic_info.BaseAddress,buffer,mem_basic_info.RegionSize,0);
							for (int bc = 0; bc < mem_basic_info.RegionSize/4; bc++)
							{
								if (buffer[bc] >= min_addr1 && (buffer[bc]%4 == 0) && buffer[bc] <= max_addr1)
								{
									for (int i1 = 0; i1 < counter; i1++)
									{
										if (buffer[bc] <= address[i1] && address[i1] <= buffer[bc]+offsets)
										{
											char str[261];
											WideCharToMultiByte(CP_ACP,0,pme32[i].szModule,-1,str,260,0,0);
											arrlist.Add("\""+gcnew String(str)+"\""+"+"+Convert::ToString((long long)ic+bc*4,16));
											arrlist1.Add(Convert::ToString((long long)(address[i1] - buffer[bc]),16));
											if (type == 1)
											{
												arrlist2.Add(".");
												arrlist3.Add(".");
											}else if(type == 2)
											{
												arrlist2.Add(Convert::ToString((long)offset1[i1],16));
												arrlist3.Add(".");
											}else if(type == 3)
											{
												arrlist2.Add(Convert::ToString((long)offset2[i1],16));
												arrlist3.Add(Convert::ToString((long)offset1[i1],16));
											}
											coutner++;
										}
									}
								}else{
									//coutner++;
								}
							}
							ic += mem_basic_info.RegionSize;
							free(buffer);
						}else
						{
							ic += mem_basic_info.RegionSize;
						}
					}else{ic += mem_basic_info.RegionSize;}
					min_addr += (long)mem_basic_info.RegionSize;
				}
			}
			return coutner;
		}


		int * PointerGenerator(HANDLE hProcess,int offsets,int Mc,MODULEENTRY32 * pme32,MEMORY_BASIC_INFORMATION * mbi,int Rc,long min_addr1,unsigned int max_addr1,unsigned int ** ModuleBuffer,unsigned int ** ModuleOFFSETS)
		{
			int * RESULTCOUNTER =(int*)calloc(1,sizeof(int));
			int soloC = 0;
			unsigned int * pmaBUFFER =(unsigned int*)calloc(1,sizeof(unsigned int));
			unsigned int * pmOFFSETS =(unsigned int*)calloc(1,sizeof(unsigned int));
			int lap = 0;
			int counter = 0;
			for (int i = 0; i < Mc; i++)
			{
				RESULTCOUNTER[soloC] = 0;
				soloC++;
				unsigned int min_addr =(long)pme32[i].modBaseAddr;
				unsigned int max_addr =(long)(pme32[i].modBaseAddr +pme32[i].modBaseSize);
				int ic = 0;
				int lo1 = 5;
				int lo2 = Rc/5;
				while (min_addr < max_addr)
				{
					MEMORY_BASIC_INFORMATION mem_basic_info = {0};
					VirtualQueryEx(hProcess,(void*)min_addr,&mem_basic_info,sizeof(MEMORY_BASIC_INFORMATION));
					char str1[8];
					char str2[8] = "Windows";
					WideCharToMultiByte(CP_ACP,0,pme32[i].szExePath+3,7,str1,260,0,0);
					str1[7] = 0;
					if (strcmp(str1,str2) != 0)
					{
						if ((mem_basic_info.Protect ==PAGE_EXECUTE_READ || PAGE_READONLY || PAGE_READWRITE)  /*&& ((long)mem_basic_info.AllocationBase == (long)pme32[i].modBaseAddr)*/)
						{
							unsigned long * buffer =(unsigned long*)malloc(mem_basic_info.RegionSize+1);
							ReadProcessMemory(hProcess,(void*)mem_basic_info.BaseAddress,buffer,mem_basic_info.RegionSize,0);
							for (int bc = 0; bc < mem_basic_info.RegionSize/4; bc++)
							{
								if (buffer[bc] >= min_addr1 && (buffer[bc]%4 == 0) && buffer[bc] <= max_addr1)
								{
									//
									int ck = 1;
									for (int i1 = 0; i1 < lo1; i1++)
									{
										if (i1 == 4)
										{
											lo2 = Rc - (Rc/5)*i1;
										}
										for (int i2 = 0; i2 <= lo2; i2++)
										{
											if (buffer[bc]+offsets > (long)mbi[(Rc/5)*i1+i2].BaseAddress && buffer[bc] < (long)mbi[i1*4+i2].BaseAddress+mbi[(Rc/5)*i1+i2].RegionSize)
											{
												//int posoffset = buffer[bc]-(long)mbi[(Rc/5)*i1+i2].BaseAddress;
												pmaBUFFER[counter] = buffer[bc];
												pmOFFSETS[counter] = ic+bc*4;
												RESULTCOUNTER[i]++;
												counter++;
												pmaBUFFER =(unsigned int*)realloc(pmaBUFFER,(counter+1)*sizeof(unsigned int));
												pmOFFSETS =(unsigned int*)realloc(pmOFFSETS,(counter+1)*sizeof(unsigned int));
												ck = 0;
												break;
											}
										}
											//counter++;
										if (ck == 0)
										{
											ck = 1;
											break;
										}
									}
									
								}
								//
							}
							ic += mem_basic_info.RegionSize;
							free(buffer);
						}else
						{
							ic += mem_basic_info.RegionSize;
						}
					}else{ic += mem_basic_info.RegionSize;}
					min_addr += (long)mem_basic_info.RegionSize;
				}
				RESULTCOUNTER = (int*)realloc(RESULTCOUNTER,(soloC+1)*sizeof(int));
			}
			*ModuleBuffer = pmaBUFFER;
			*ModuleOFFSETS =pmOFFSETS;
			return RESULTCOUNTER;
		}

		//new version of scanning the memory for this shit :D

		int ScanPointerNV(int * counter,int offsetMAX,unsigned int * mBUFFER,unsigned int * mOFFSETS,long * address,int AddrCounter,int mCounter,MODULEENTRY32 * pme32,int * offset1,int * offset2,int scanPower)
		{
			int mcC = 0;
			int ResultCounter = 0;
			for (int mc = 0; mc < mCounter; mc++)
			{
				for (int i = mcC; i < mcC+counter[mc]; i++)
				{
					for (int ADDRc = 0; ADDRc < AddrCounter; ADDRc++)
					{
						if (mBUFFER[i] <= address[ADDRc] && mBUFFER[i]+offsetMAX >= address[ADDRc])
						{
							arrlist.Add(gcnew String(pme32[mc].szModule)+"+"+Convert::ToString((long long)mOFFSETS[i],16));
							arrlist1.Add(Convert::ToString((long long)address[ADDRc] - mBUFFER[i],16));
							if (scanPower == 1)
							{
								arrlist2.Add(".");
								arrlist3.Add(".");
							}else if (scanPower == 2)
							{
								arrlist2.Add(Convert::ToString(offset1[ADDRc],16));
								arrlist3.Add(".");
							}
							else if(scanPower == 3)
							{
								arrlist2.Add(Convert::ToString(offset2[ADDRc],16));
								arrlist3.Add(Convert::ToString(offset1[ADDRc],16));
							}
							ResultCounter++;
						}
					}
				}
				mcC += counter[mc];
			}
			return ResultCounter;
		}


	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~PointerScanner()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^  button1;
	protected: 
	private: System::Windows::Forms::Label^  label1;
	private: System::Windows::Forms::TextBox^  textBox1;
	private: System::Windows::Forms::TextBox^  textBox2;
	private: System::Windows::Forms::Label^  label2;
	private: System::Windows::Forms::Label^  label3;
	private: System::Windows::Forms::ComboBox^  comboBox1;
	private: System::Windows::Forms::Button^  button2;
	private: System::Windows::Forms::CheckBox^  checkBox1;
	private: System::Windows::Forms::CheckBox^  checkBox2;
	private: System::Windows::Forms::TextBox^  textBox3;
	private: System::Windows::Forms::TextBox^  textBox4;
	private: System::Windows::Forms::ListView^  listView1;
	private: System::Windows::Forms::ColumnHeader^  columnHeader1;
	private: System::Windows::Forms::ColumnHeader^  columnHeader2;





	private:
		/// <summary>
		/// Required designer variable.
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		void InitializeComponent(void)
		{
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->textBox2 = (gcnew System::Windows::Forms::TextBox());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->comboBox1 = (gcnew System::Windows::Forms::ComboBox());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->checkBox1 = (gcnew System::Windows::Forms::CheckBox());
			this->checkBox2 = (gcnew System::Windows::Forms::CheckBox());
			this->textBox3 = (gcnew System::Windows::Forms::TextBox());
			this->textBox4 = (gcnew System::Windows::Forms::TextBox());
			this->listView1 = (gcnew System::Windows::Forms::ListView());
			this->columnHeader1 = (gcnew System::Windows::Forms::ColumnHeader());
			this->columnHeader2 = (gcnew System::Windows::Forms::ColumnHeader());
			this->columnHeader6 = (gcnew System::Windows::Forms::ColumnHeader());
			this->columnHeader3 = (gcnew System::Windows::Forms::ColumnHeader());
			this->SuspendLayout();
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(689, 14);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(84, 22);
			this->button1->TabIndex = 0;
			this->button1->Text = L"Scan";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &PointerScanner::button1_Click);
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(9, 16);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(54, 13);
			this->label1->TabIndex = 1;
			this->label1->Text = L"Address : ";
			// 
			// textBox1
			// 
			this->textBox1->Location = System::Drawing::Point(66, 13);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(153, 20);
			this->textBox1->TabIndex = 2;
			this->textBox1->Text = L"395240";
			// 
			// textBox2
			// 
			this->textBox2->Location = System::Drawing::Point(334, 14);
			this->textBox2->Name = L"textBox2";
			this->textBox2->Size = System::Drawing::Size(153, 20);
			this->textBox2->TabIndex = 4;
			this->textBox2->Text = L"2047";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(223, 17);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(108, 13);
			this->label2->TabIndex = 3;
			this->label2->Text = L"Distnace Of Offsets : ";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(489, 18);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(54, 13);
			this->label3->TabIndex = 5;
			this->label3->Text = L"Process : ";
			// 
			// comboBox1
			// 
			this->comboBox1->FormattingEnabled = true;
			this->comboBox1->Location = System::Drawing::Point(548, 15);
			this->comboBox1->Name = L"comboBox1";
			this->comboBox1->Size = System::Drawing::Size(135, 21);
			this->comboBox1->TabIndex = 6;
			// 
			// button2
			// 
			this->button2->Enabled = false;
			this->button2->Location = System::Drawing::Point(654, 46);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(119, 23);
			this->button2->TabIndex = 7;
			this->button2->Text = L"ReScan";
			this->button2->UseVisualStyleBackColor = true;
			// 
			// checkBox1
			// 
			this->checkBox1->AutoSize = true;
			this->checkBox1->Enabled = false;
			this->checkBox1->Location = System::Drawing::Point(12, 48);
			this->checkBox1->Name = L"checkBox1";
			this->checkBox1->Size = System::Drawing::Size(115, 17);
			this->checkBox1->TabIndex = 8;
			this->checkBox1->Text = L"Rescan The Value";
			this->checkBox1->UseVisualStyleBackColor = true;
			// 
			// checkBox2
			// 
			this->checkBox2->AutoSize = true;
			this->checkBox2->Enabled = false;
			this->checkBox2->Location = System::Drawing::Point(367, 49);
			this->checkBox2->Name = L"checkBox2";
			this->checkBox2->Size = System::Drawing::Size(126, 17);
			this->checkBox2->TabIndex = 9;
			this->checkBox2->Text = L"Rescan The Address";
			this->checkBox2->UseVisualStyleBackColor = true;
			// 
			// textBox3
			// 
			this->textBox3->Enabled = false;
			this->textBox3->Location = System::Drawing::Point(130, 47);
			this->textBox3->Name = L"textBox3";
			this->textBox3->Size = System::Drawing::Size(153, 20);
			this->textBox3->TabIndex = 10;
			// 
			// textBox4
			// 
			this->textBox4->Enabled = false;
			this->textBox4->Location = System::Drawing::Point(495, 47);
			this->textBox4->Name = L"textBox4";
			this->textBox4->Size = System::Drawing::Size(153, 20);
			this->textBox4->TabIndex = 11;
			// 
			// listView1
			// 
			this->listView1->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(4) {this->columnHeader1, this->columnHeader2, 
				this->columnHeader6, this->columnHeader3});
			this->listView1->Location = System::Drawing::Point(12, 73);
			this->listView1->Name = L"listView1";
			this->listView1->Size = System::Drawing::Size(761, 558);
			this->listView1->TabIndex = 12;
			this->listView1->UseCompatibleStateImageBehavior = false;
			this->listView1->View = System::Windows::Forms::View::Details;
			this->listView1->VirtualMode = true;
			this->listView1->RetrieveVirtualItem += gcnew System::Windows::Forms::RetrieveVirtualItemEventHandler(this, &PointerScanner::listView1_RetrieveVirtualItem);
			// 
			// columnHeader1
			// 
			this->columnHeader1->Text = L"Base";
			this->columnHeader1->Width = 125;
			// 
			// columnHeader2
			// 
			this->columnHeader2->Text = L"Offset 1";
			this->columnHeader2->Width = 125;
			// 
			// columnHeader6
			// 
			this->columnHeader6->Text = L"Offset 2";
			this->columnHeader6->Width = 125;
			// 
			// columnHeader3
			// 
			this->columnHeader3->Text = L"Offset 3";
			this->columnHeader3->Width = 125;
			// 
			// PointerScanner
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(778, 633);
			this->Controls->Add(this->listView1);
			this->Controls->Add(this->textBox4);
			this->Controls->Add(this->textBox3);
			this->Controls->Add(this->checkBox2);
			this->Controls->Add(this->checkBox1);
			this->Controls->Add(this->button2);
			this->Controls->Add(this->comboBox1);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->textBox2);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->button1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedSingle;
			this->Name = L"PointerScanner";
			this->Text = L"PointerScanner";
			this->Load += gcnew System::EventHandler(this, &PointerScanner::PointerScanner_Load);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void PointerScanner_Load(System::Object^  sender, System::EventArgs^  e) {
				 
				 array<Process^>^ pr = Process::GetProcesses();
				 for each (Process^ process in pr)
				 {
					 comboBox1->Items->Add(process->ProcessName);
				 }
			 }
private: System::Void button1_Click(System::Object^  sender, System::EventArgs^  e) {

			 //ScanMemory(OpenProcess(PROCESS_ALL_ACCESS,0,Process::GetProcessesByName(comboBox1->Text)[0]->Id),395240,2047,counter);
			 //MessageBox::Show(Convert::ToString(*counter));
			// int f = PointerScan(OpenProcess(PROCESS_ALL_ACCESS,0,Process::GetProcessesByName(comboBox1->Text)[0]->Id),Process::GetProcessesByName(comboBox1->Text)[0]->Id,Convert::ToInt32(textBox1->Text),Convert::ToInt32(textBox2->Text));
			 //int counter = PointerScanNew(OpenProcess(PROCESS_ALL_ACCESS,0,Process::GetProcessesByName(comboBox1->Text)[0]->Id),Process::GetProcessesByName(comboBox1->Text)[0]->Id,Convert::ToInt32(textBox1->Text));
			 //fc1.PointerScanner(OpenProcess(PROCESS_ALL_ACCESS,0,Process::GetProcessesByName(comboBox1->Text)[0]->Id),Process::GetProcessesByName(comboBox1->Text)[0]->Id,99999);
			 //PointerScan(OpenProcess(PROCESS_ALL_ACCESS,0,Process::GetProcessesByName(comboBox1->Text)[0]->Id),395240,2047,Process::GetProcessesByName(comboBox1->Text)[0]->Id);
			  int f = GeneratePointerMap(OpenProcess(PROCESS_ALL_ACCESS,0,Process::GetProcessesByName(comboBox1->Text)[0]->Id),Process::GetProcessesByName(comboBox1->Text)[0]->Id,Convert::ToInt32(textBox2->Text),Convert::ToInt32(textBox1->Text));
			  listView1->VirtualListSize = f;
		 }
private: System::Void listView1_RetrieveVirtualItem(System::Object^  sender, System::Windows::Forms::RetrieveVirtualItemEventArgs^  e) {
			 ListViewItem^ lvi = gcnew ListViewItem(arrlist[e->ItemIndex]->ToString());
			 lvi->SubItems->Add(arrlist1[e->ItemIndex]->ToString());
			 lvi->SubItems->Add(arrlist2[e->ItemIndex]->ToString());
			 lvi->SubItems->Add(arrlist3[e->ItemIndex]->ToString());
			 //lvi->SubItems->Add(arrlist4[e->ItemIndex]->ToString());
			 e->Item = lvi;
		 }
};
}
