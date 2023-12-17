#pragma once
#include "Crypto.h"
#include <stdlib.h>
#include <string.h>
#include <msclr\marshal_cppstd.h>

namespace SecurityProject {

	std::string data;
	using namespace System;
	using namespace msclr::interop;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::IO;

	/// <summary>
	/// Summary for SecurityForm
	/// </summary>
	public ref class SecurityForm : public System::Windows::Forms::Form
	{

	private: Crypto::CryptoClient* crypto;
	private: Crypto::CryptoClient* crypto1;
	private: Crypto::CryptoClient* crypto2;
	private: System::Windows::Forms::TabPage^ tabPage4;
	private: System::Windows::Forms::RichTextBox^ richTextBox1;
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::RichTextBox^ richTextBox2;
	private: System::Windows::Forms::Button^ sendmessageclient2;
	private: System::Windows::Forms::RichTextBox^ richTextBox4;
	private: System::Windows::Forms::RichTextBox^ richTextBox3;
	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::Button^ sendmessageclient1;
	private: System::Windows::Forms::Button^ button3;
	private: System::Windows::Forms::Button^ clearmessages;

	private: Crypto::CryptoClient* client1;
	private: Crypto::CryptoClient* client2;
	private: bool connected;

	public:
		SecurityForm(void)
		{
			InitializeComponent();
			//
			//TODO: Add the constructor code here
			//
			AES::AESKey::generateKey();
			crypto = new Crypto::CryptoClient("Crypto1");
			crypto1 = new Crypto::CryptoClient("Crypto2");
			crypto2 = new Crypto::CryptoClient("Crypto3");
			client1 = new Crypto::CryptoClient("Client1");
			client2 = new Crypto::CryptoClient("Client2");
			displayLabel->Text = "";
			displaylabel1->Text = "";
			displaylabel2->Text = "";
			label1->Text = "AES Encryption and Decryption";
			this->pictureBox1->SizeMode = PictureBoxSizeMode::Zoom;
			connected = false;
		}

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~SecurityForm()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Label^ displayLabel;
	protected:
	private: System::Windows::Forms::Button^ AESEncrypt;
	private: System::Windows::Forms::Button^ AESDecrypt;
	private: System::Windows::Forms::Button^ RSASign;
	private: System::Windows::Forms::Button^ RSAVerify;
	private: System::Windows::Forms::Button^ SignAndEncrypt;
	private: System::Windows::Forms::Button^ DecryptAndVerify;
	private: System::Windows::Forms::Button^ BrowseFile;
	private: System::Windows::Forms::Button^ button1;
	private: System::Windows::Forms::Button^ button2;
	private: System::Windows::Forms::RichTextBox^ TextBox;
	private: System::Windows::Forms::OpenFileDialog^ openFileDialog1;


	private: Stream^ myStream;
	private: StreamWriter^ myStreamWriter;
	private: String^ strFileName;
	private: String^ TextContent;
	private: Stream^ myStream1;
	private: StreamWriter^ myStreamWriter1;
	private: String^ strFileName1;
	private: String^ TextContent1;
	private: Stream^ myStream2;
	private: StreamWriter^ myStreamWriter2;
	private: String^ strFileName2;
	private: String^ TextContent2;
	private: String^ MessageClient1;
	private: String^ MessageClient2;
	private: String^ publicClient1Key;
	private: String^ publicClient2Key;
	private: System::Windows::Forms::TabControl^ tabControl1;
	private: System::Windows::Forms::TabPage^ tabPage1;

	private: System::Windows::Forms::TabPage^ tabPage2;



	private: System::Windows::Forms::RichTextBox^ TextBox1;

	private: System::Windows::Forms::Button^ button6;
	private: System::Windows::Forms::Label^ displaylabel1;
	private: System::Windows::Forms::Button^ browsefile1;
	private: System::Windows::Forms::TabPage^ tabPage3;


	private: System::Windows::Forms::Label^ displaylabel2;

	private: System::Windows::Forms::Button^ browsefile2;
	private: System::Windows::Forms::Button^ button4;
	private: System::Windows::Forms::RichTextBox^ TextBox2;

	private: System::Windows::Forms::Panel^ panel1;
	private: System::Windows::Forms::OpenFileDialog^ openFileDialog2;
	private: System::Windows::Forms::OpenFileDialog^ openFileDialog3;
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::PictureBox^ pictureBox1;

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
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(SecurityForm::typeid));
			this->displayLabel = (gcnew System::Windows::Forms::Label());
			this->AESEncrypt = (gcnew System::Windows::Forms::Button());
			this->AESDecrypt = (gcnew System::Windows::Forms::Button());
			this->RSASign = (gcnew System::Windows::Forms::Button());
			this->RSAVerify = (gcnew System::Windows::Forms::Button());
			this->SignAndEncrypt = (gcnew System::Windows::Forms::Button());
			this->DecryptAndVerify = (gcnew System::Windows::Forms::Button());
			this->BrowseFile = (gcnew System::Windows::Forms::Button());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->TextBox = (gcnew System::Windows::Forms::RichTextBox());
			this->openFileDialog1 = (gcnew System::Windows::Forms::OpenFileDialog());
			this->tabControl1 = (gcnew System::Windows::Forms::TabControl());
			this->tabPage1 = (gcnew System::Windows::Forms::TabPage());
			this->tabPage2 = (gcnew System::Windows::Forms::TabPage());
			this->button6 = (gcnew System::Windows::Forms::Button());
			this->displaylabel1 = (gcnew System::Windows::Forms::Label());
			this->browsefile1 = (gcnew System::Windows::Forms::Button());
			this->TextBox1 = (gcnew System::Windows::Forms::RichTextBox());
			this->tabPage3 = (gcnew System::Windows::Forms::TabPage());
			this->displaylabel2 = (gcnew System::Windows::Forms::Label());
			this->browsefile2 = (gcnew System::Windows::Forms::Button());
			this->button4 = (gcnew System::Windows::Forms::Button());
			this->TextBox2 = (gcnew System::Windows::Forms::RichTextBox());
			this->tabPage4 = (gcnew System::Windows::Forms::TabPage());
			this->button3 = (gcnew System::Windows::Forms::Button());
			this->clearmessages = (gcnew System::Windows::Forms::Button());
			this->sendmessageclient2 = (gcnew System::Windows::Forms::Button());
			this->richTextBox4 = (gcnew System::Windows::Forms::RichTextBox());
			this->richTextBox3 = (gcnew System::Windows::Forms::RichTextBox());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->sendmessageclient1 = (gcnew System::Windows::Forms::Button());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->richTextBox2 = (gcnew System::Windows::Forms::RichTextBox());
			this->richTextBox1 = (gcnew System::Windows::Forms::RichTextBox());
			this->pictureBox1 = (gcnew System::Windows::Forms::PictureBox());
			this->panel1 = (gcnew System::Windows::Forms::Panel());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->openFileDialog2 = (gcnew System::Windows::Forms::OpenFileDialog());
			this->openFileDialog3 = (gcnew System::Windows::Forms::OpenFileDialog());
			this->tabControl1->SuspendLayout();
			this->tabPage1->SuspendLayout();
			this->tabPage2->SuspendLayout();
			this->tabPage3->SuspendLayout();
			this->tabPage4->SuspendLayout();
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->BeginInit();
			this->panel1->SuspendLayout();
			this->SuspendLayout();
			// 
			// displayLabel
			// 
			this->displayLabel->AutoSize = true;
			this->displayLabel->BackColor = System::Drawing::SystemColors::ActiveBorder;
			this->displayLabel->Font = (gcnew System::Drawing::Font(L"Times New Roman", 18, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->displayLabel->ForeColor = System::Drawing::Color::DarkGreen;
			this->displayLabel->Location = System::Drawing::Point(8, 452);
			this->displayLabel->Name = L"displayLabel";
			this->displayLabel->Size = System::Drawing::Size(105, 35);
			this->displayLabel->TabIndex = 0;
			this->displayLabel->Text = L"display";
			// 
			// AESEncrypt
			// 
			this->AESEncrypt->Location = System::Drawing::Point(865, 443);
			this->AESEncrypt->Name = L"AESEncrypt";
			this->AESEncrypt->Size = System::Drawing::Size(100, 31);
			this->AESEncrypt->TabIndex = 1;
			this->AESEncrypt->Text = L"AES Encrypt";
			this->AESEncrypt->UseVisualStyleBackColor = true;
			this->AESEncrypt->Click += gcnew System::EventHandler(this, &SecurityForm::AESEncrypt_Click);
			// 
			// AESDecrypt
			// 
			this->AESDecrypt->Location = System::Drawing::Point(971, 443);
			this->AESDecrypt->Name = L"AESDecrypt";
			this->AESDecrypt->Size = System::Drawing::Size(100, 31);
			this->AESDecrypt->TabIndex = 2;
			this->AESDecrypt->Text = L"AES Decrypt";
			this->AESDecrypt->UseVisualStyleBackColor = true;
			this->AESDecrypt->Click += gcnew System::EventHandler(this, &SecurityForm::AESDecrypt_Click);
			// 
			// RSASign
			// 
			this->RSASign->Location = System::Drawing::Point(864, 445);
			this->RSASign->Name = L"RSASign";
			this->RSASign->Size = System::Drawing::Size(100, 31);
			this->RSASign->TabIndex = 3;
			this->RSASign->Text = L"RSA Sign";
			this->RSASign->UseVisualStyleBackColor = true;
			this->RSASign->Click += gcnew System::EventHandler(this, &SecurityForm::RSASign_Click);
			// 
			// RSAVerify
			// 
			this->RSAVerify->Location = System::Drawing::Point(969, 445);
			this->RSAVerify->Name = L"RSAVerify";
			this->RSAVerify->Size = System::Drawing::Size(100, 31);
			this->RSAVerify->TabIndex = 4;
			this->RSAVerify->Text = L"RSA Verify";
			this->RSAVerify->UseVisualStyleBackColor = true;
			this->RSAVerify->Click += gcnew System::EventHandler(this, &SecurityForm::RSAVerify_Click);
			// 
			// SignAndEncrypt
			// 
			this->SignAndEncrypt->Location = System::Drawing::Point(817, 443);
			this->SignAndEncrypt->Name = L"SignAndEncrypt";
			this->SignAndEncrypt->Size = System::Drawing::Size(123, 31);
			this->SignAndEncrypt->TabIndex = 5;
			this->SignAndEncrypt->Text = L"Sign And Encrypt";
			this->SignAndEncrypt->UseVisualStyleBackColor = true;
			this->SignAndEncrypt->Click += gcnew System::EventHandler(this, &SecurityForm::SignAndEncrypt_Click);
			// 
			// DecryptAndVerify
			// 
			this->DecryptAndVerify->Location = System::Drawing::Point(946, 443);
			this->DecryptAndVerify->Name = L"DecryptAndVerify";
			this->DecryptAndVerify->Size = System::Drawing::Size(123, 31);
			this->DecryptAndVerify->TabIndex = 6;
			this->DecryptAndVerify->Text = L"Decrypt And Verify";
			this->DecryptAndVerify->UseVisualStyleBackColor = true;
			this->DecryptAndVerify->Click += gcnew System::EventHandler(this, &SecurityForm::DecryptAndVerify_Click);
			// 
			// BrowseFile
			// 
			this->BrowseFile->Location = System::Drawing::Point(1077, 443);
			this->BrowseFile->Name = L"BrowseFile";
			this->BrowseFile->Size = System::Drawing::Size(100, 31);
			this->BrowseFile->TabIndex = 7;
			this->BrowseFile->Text = L"Browse File";
			this->BrowseFile->UseVisualStyleBackColor = true;
			this->BrowseFile->Click += gcnew System::EventHandler(this, &SecurityForm::BrowseFile_Click);
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(137, 418);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(123, 31);
			this->button1->TabIndex = 8;
			this->button1->Text = L"Generate RSA Keys";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &SecurityForm::button1_Click);
			// 
			// button2
			// 
			this->button2->Location = System::Drawing::Point(6, 418);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(123, 31);
			this->button2->TabIndex = 9;
			this->button2->Text = L"Generate AES Key";
			this->button2->UseVisualStyleBackColor = true;
			this->button2->Click += gcnew System::EventHandler(this, &SecurityForm::button2_Click);
			// 
			// TextBox
			// 
			this->TextBox->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->TextBox->Location = System::Drawing::Point(6, 3);
			this->TextBox->Name = L"TextBox";
			this->TextBox->Size = System::Drawing::Size(1169, 409);
			this->TextBox->TabIndex = 10;
			this->TextBox->Text = L"";
			this->TextBox->TextChanged += gcnew System::EventHandler(this, &SecurityForm::TextBox_TextChanged);
			// 
			// openFileDialog1
			// 
			this->openFileDialog1->FileName = L"openFileDialog1";
			// 
			// tabControl1
			// 
			this->tabControl1->Controls->Add(this->tabPage1);
			this->tabControl1->Controls->Add(this->tabPage2);
			this->tabControl1->Controls->Add(this->tabPage3);
			this->tabControl1->Controls->Add(this->tabPage4);
			this->tabControl1->Location = System::Drawing::Point(0, 43);
			this->tabControl1->Name = L"tabControl1";
			this->tabControl1->SelectedIndex = 0;
			this->tabControl1->Size = System::Drawing::Size(1191, 517);
			this->tabControl1->TabIndex = 11;
			this->tabControl1->Click += gcnew System::EventHandler(this, &SecurityForm::tabControl1_Click);
			// 
			// tabPage1
			// 
			this->tabPage1->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"tabPage1.BackgroundImage")));
			this->tabPage1->BackgroundImageLayout = System::Windows::Forms::ImageLayout::Stretch;
			this->tabPage1->Controls->Add(this->TextBox);
			this->tabPage1->Controls->Add(this->displayLabel);
			this->tabPage1->Controls->Add(this->button2);
			this->tabPage1->Controls->Add(this->BrowseFile);
			this->tabPage1->Controls->Add(this->AESEncrypt);
			this->tabPage1->Controls->Add(this->AESDecrypt);
			this->tabPage1->Location = System::Drawing::Point(4, 22);
			this->tabPage1->Name = L"tabPage1";
			this->tabPage1->Padding = System::Windows::Forms::Padding(3);
			this->tabPage1->Size = System::Drawing::Size(1183, 491);
			this->tabPage1->TabIndex = 0;
			this->tabPage1->Text = L"AES";
			this->tabPage1->UseVisualStyleBackColor = true;
			// 
			// tabPage2
			// 
			this->tabPage2->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"tabPage2.BackgroundImage")));
			this->tabPage2->BackgroundImageLayout = System::Windows::Forms::ImageLayout::Stretch;
			this->tabPage2->Controls->Add(this->button6);
			this->tabPage2->Controls->Add(this->displaylabel1);
			this->tabPage2->Controls->Add(this->browsefile1);
			this->tabPage2->Controls->Add(this->TextBox1);
			this->tabPage2->Controls->Add(this->RSAVerify);
			this->tabPage2->Controls->Add(this->RSASign);
			this->tabPage2->Location = System::Drawing::Point(4, 22);
			this->tabPage2->Name = L"tabPage2";
			this->tabPage2->Padding = System::Windows::Forms::Padding(3);
			this->tabPage2->Size = System::Drawing::Size(1183, 491);
			this->tabPage2->TabIndex = 1;
			this->tabPage2->Text = L"Sign And Verify";
			this->tabPage2->UseVisualStyleBackColor = true;
			// 
			// button6
			// 
			this->button6->Location = System::Drawing::Point(8, 418);
			this->button6->Name = L"button6";
			this->button6->Size = System::Drawing::Size(123, 31);
			this->button6->TabIndex = 14;
			this->button6->Text = L"Generate RSA Keys";
			this->button6->UseVisualStyleBackColor = true;
			this->button6->Click += gcnew System::EventHandler(this, &SecurityForm::button6_Click);
			// 
			// displaylabel1
			// 
			this->displaylabel1->AutoSize = true;
			this->displaylabel1->BackColor = System::Drawing::SystemColors::ActiveBorder;
			this->displaylabel1->Font = (gcnew System::Drawing::Font(L"Times New Roman", 18, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->displaylabel1->ForeColor = System::Drawing::SystemColors::ActiveCaptionText;
			this->displaylabel1->Location = System::Drawing::Point(8, 452);
			this->displaylabel1->Name = L"displaylabel1";
			this->displaylabel1->Size = System::Drawing::Size(105, 35);
			this->displaylabel1->TabIndex = 13;
			this->displaylabel1->Text = L"display";
			// 
			// browsefile1
			// 
			this->browsefile1->Location = System::Drawing::Point(1075, 445);
			this->browsefile1->Name = L"browsefile1";
			this->browsefile1->Size = System::Drawing::Size(100, 31);
			this->browsefile1->TabIndex = 12;
			this->browsefile1->Text = L"Browse File";
			this->browsefile1->UseVisualStyleBackColor = true;
			this->browsefile1->Click += gcnew System::EventHandler(this, &SecurityForm::browsefile1_Click);
			// 
			// TextBox1
			// 
			this->TextBox1->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->TextBox1->Location = System::Drawing::Point(6, 3);
			this->TextBox1->Name = L"TextBox1";
			this->TextBox1->Size = System::Drawing::Size(1169, 409);
			this->TextBox1->TabIndex = 11;
			this->TextBox1->Text = L"";
			this->TextBox1->TextChanged += gcnew System::EventHandler(this, &SecurityForm::TextBox1_TextChanged);
			// 
			// tabPage3
			// 
			this->tabPage3->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"tabPage3.BackgroundImage")));
			this->tabPage3->BackgroundImageLayout = System::Windows::Forms::ImageLayout::Stretch;
			this->tabPage3->Controls->Add(this->displaylabel2);
			this->tabPage3->Controls->Add(this->browsefile2);
			this->tabPage3->Controls->Add(this->button4);
			this->tabPage3->Controls->Add(this->SignAndEncrypt);
			this->tabPage3->Controls->Add(this->DecryptAndVerify);
			this->tabPage3->Controls->Add(this->button1);
			this->tabPage3->Controls->Add(this->TextBox2);
			this->tabPage3->Location = System::Drawing::Point(4, 22);
			this->tabPage3->Name = L"tabPage3";
			this->tabPage3->Padding = System::Windows::Forms::Padding(3);
			this->tabPage3->Size = System::Drawing::Size(1183, 491);
			this->tabPage3->TabIndex = 2;
			this->tabPage3->Text = L"AES With Sign And Verify";
			this->tabPage3->UseVisualStyleBackColor = true;
			// 
			// displaylabel2
			// 
			this->displaylabel2->AutoSize = true;
			this->displaylabel2->BackColor = System::Drawing::SystemColors::ActiveBorder;
			this->displaylabel2->Font = (gcnew System::Drawing::Font(L"Times New Roman", 18, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->displaylabel2->Location = System::Drawing::Point(8, 452);
			this->displaylabel2->Name = L"displaylabel2";
			this->displaylabel2->Size = System::Drawing::Size(105, 35);
			this->displaylabel2->TabIndex = 15;
			this->displaylabel2->Text = L"display";
			// 
			// browsefile2
			// 
			this->browsefile2->Location = System::Drawing::Point(1075, 443);
			this->browsefile2->Name = L"browsefile2";
			this->browsefile2->Size = System::Drawing::Size(100, 31);
			this->browsefile2->TabIndex = 14;
			this->browsefile2->Text = L"Browse File";
			this->browsefile2->UseVisualStyleBackColor = true;
			this->browsefile2->Click += gcnew System::EventHandler(this, &SecurityForm::browsefile2_Click);
			// 
			// button4
			// 
			this->button4->Location = System::Drawing::Point(8, 418);
			this->button4->Name = L"button4";
			this->button4->Size = System::Drawing::Size(123, 31);
			this->button4->TabIndex = 13;
			this->button4->Text = L"Generate AES Key";
			this->button4->UseVisualStyleBackColor = true;
			this->button4->Click += gcnew System::EventHandler(this, &SecurityForm::button4_Click);
			// 
			// TextBox2
			// 
			this->TextBox2->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->TextBox2->Location = System::Drawing::Point(6, 3);
			this->TextBox2->Name = L"TextBox2";
			this->TextBox2->Size = System::Drawing::Size(1169, 409);
			this->TextBox2->TabIndex = 12;
			this->TextBox2->Text = L"";
			this->TextBox2->TextChanged += gcnew System::EventHandler(this, &SecurityForm::TextBox2_TextChanged);
			// 
			// tabPage4
			// 
			this->tabPage4->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"tabPage4.BackgroundImage")));
			this->tabPage4->BackgroundImageLayout = System::Windows::Forms::ImageLayout::Stretch;
			this->tabPage4->Controls->Add(this->button3);
			this->tabPage4->Controls->Add(this->clearmessages);
			this->tabPage4->Controls->Add(this->sendmessageclient2);
			this->tabPage4->Controls->Add(this->richTextBox4);
			this->tabPage4->Controls->Add(this->richTextBox3);
			this->tabPage4->Controls->Add(this->label3);
			this->tabPage4->Controls->Add(this->sendmessageclient1);
			this->tabPage4->Controls->Add(this->label2);
			this->tabPage4->Controls->Add(this->richTextBox2);
			this->tabPage4->Controls->Add(this->richTextBox1);
			this->tabPage4->Location = System::Drawing::Point(4, 22);
			this->tabPage4->Name = L"tabPage4";
			this->tabPage4->Padding = System::Windows::Forms::Padding(3);
			this->tabPage4->Size = System::Drawing::Size(1183, 491);
			this->tabPage4->TabIndex = 3;
			this->tabPage4->Text = L"Secure Chat";
			this->tabPage4->UseVisualStyleBackColor = true;
			// 
			// button3
			// 
			this->button3->Location = System::Drawing::Point(436, 416);
			this->button3->Name = L"button3";
			this->button3->Size = System::Drawing::Size(292, 31);
			this->button3->TabIndex = 23;
			this->button3->Text = L"Start Connection";
			this->button3->UseVisualStyleBackColor = true;
			this->button3->Click += gcnew System::EventHandler(this, &SecurityForm::button3_Click);
			// 
			// clearmessages
			// 
			this->clearmessages->Location = System::Drawing::Point(436, 453);
			this->clearmessages->Name = L"clearmessages";
			this->clearmessages->Size = System::Drawing::Size(292, 31);
			this->clearmessages->TabIndex = 22;
			this->clearmessages->Text = L"Clear Messages";
			this->clearmessages->UseVisualStyleBackColor = true;
			this->clearmessages->Click += gcnew System::EventHandler(this, &SecurityForm::clearmessages_Click);
			// 
			// sendmessageclient2
			// 
			this->sendmessageclient2->Location = System::Drawing::Point(883, 453);
			this->sendmessageclient2->Name = L"sendmessageclient2";
			this->sendmessageclient2->Size = System::Drawing::Size(292, 31);
			this->sendmessageclient2->TabIndex = 21;
			this->sendmessageclient2->Text = L"Send Message";
			this->sendmessageclient2->UseVisualStyleBackColor = true;
			this->sendmessageclient2->Click += gcnew System::EventHandler(this, &SecurityForm::sendmessageclient2_Click);
			// 
			// richTextBox4
			// 
			this->richTextBox4->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->richTextBox4->Location = System::Drawing::Point(879, 398);
			this->richTextBox4->Name = L"richTextBox4";
			this->richTextBox4->Size = System::Drawing::Size(296, 49);
			this->richTextBox4->TabIndex = 20;
			this->richTextBox4->Text = L"";
			this->richTextBox4->TextChanged += gcnew System::EventHandler(this, &SecurityForm::richTextBox4_TextChanged);
			// 
			// richTextBox3
			// 
			this->richTextBox3->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->richTextBox3->Location = System::Drawing::Point(879, 62);
			this->richTextBox3->Name = L"richTextBox3";
			this->richTextBox3->ReadOnly = true;
			this->richTextBox3->Size = System::Drawing::Size(296, 330);
			this->richTextBox3->TabIndex = 19;
			this->richTextBox3->Text = L"";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->BackColor = System::Drawing::SystemColors::ActiveBorder;
			this->label3->Font = (gcnew System::Drawing::Font(L"Times New Roman", 18, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label3->Location = System::Drawing::Point(873, 14);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(107, 35);
			this->label3->TabIndex = 18;
			this->label3->Text = L"Client2";
			// 
			// sendmessageclient1
			// 
			this->sendmessageclient1->Location = System::Drawing::Point(12, 453);
			this->sendmessageclient1->Name = L"sendmessageclient1";
			this->sendmessageclient1->Size = System::Drawing::Size(292, 31);
			this->sendmessageclient1->TabIndex = 17;
			this->sendmessageclient1->Text = L"Send Message";
			this->sendmessageclient1->UseVisualStyleBackColor = true;
			this->sendmessageclient1->Click += gcnew System::EventHandler(this, &SecurityForm::sendmessageclient1_Click);
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->BackColor = System::Drawing::SystemColors::ActiveBorder;
			this->label2->Font = (gcnew System::Drawing::Font(L"Times New Roman", 18, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label2->Location = System::Drawing::Point(6, 14);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(107, 35);
			this->label2->TabIndex = 16;
			this->label2->Text = L"Client1";
			// 
			// richTextBox2
			// 
			this->richTextBox2->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->richTextBox2->Location = System::Drawing::Point(8, 398);
			this->richTextBox2->Name = L"richTextBox2";
			this->richTextBox2->Size = System::Drawing::Size(296, 49);
			this->richTextBox2->TabIndex = 12;
			this->richTextBox2->Text = L"";
			this->richTextBox2->TextChanged += gcnew System::EventHandler(this, &SecurityForm::richTextBox2_TextChanged);
			// 
			// richTextBox1
			// 
			this->richTextBox1->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->richTextBox1->Location = System::Drawing::Point(8, 62);
			this->richTextBox1->Name = L"richTextBox1";
			this->richTextBox1->ReadOnly = true;
			this->richTextBox1->Size = System::Drawing::Size(296, 330);
			this->richTextBox1->TabIndex = 11;
			this->richTextBox1->Text = L"";
			// 
			// pictureBox1
			// 
			this->pictureBox1->Image = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"pictureBox1.Image")));
			this->pictureBox1->Location = System::Drawing::Point(1127, 3);
			this->pictureBox1->Name = L"pictureBox1";
			this->pictureBox1->Size = System::Drawing::Size(48, 30);
			this->pictureBox1->TabIndex = 2;
			this->pictureBox1->TabStop = false;
			// 
			// panel1
			// 
			this->panel1->BackColor = System::Drawing::SystemColors::ActiveCaption;
			this->panel1->Controls->Add(this->pictureBox1);
			this->panel1->Controls->Add(this->label1);
			this->panel1->Location = System::Drawing::Point(4, 1);
			this->panel1->Name = L"panel1";
			this->panel1->Size = System::Drawing::Size(1187, 36);
			this->panel1->TabIndex = 12;
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->BackColor = System::Drawing::Color::Transparent;
			this->label1->Font = (gcnew System::Drawing::Font(L"Times New Roman", 13.8F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->label1->ForeColor = System::Drawing::SystemColors::ActiveCaptionText;
			this->label1->Location = System::Drawing::Point(440, 8);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(334, 25);
			this->label1->TabIndex = 1;
			this->label1->Text = L"AES Encryption and Decryption";
			// 
			// openFileDialog2
			// 
			this->openFileDialog2->FileName = L"openFileDialog2";
			// 
			// openFileDialog3
			// 
			this->openFileDialog3->FileName = L"openFileDialog3";
			// 
			// SecurityForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(1191, 561);
			this->Controls->Add(this->panel1);
			this->Controls->Add(this->tabControl1);
			this->Margin = System::Windows::Forms::Padding(2);
			this->Name = L"SecurityForm";
			this->Text = L"SecurityForm";
			this->tabControl1->ResumeLayout(false);
			this->tabPage1->ResumeLayout(false);
			this->tabPage1->PerformLayout();
			this->tabPage2->ResumeLayout(false);
			this->tabPage2->PerformLayout();
			this->tabPage3->ResumeLayout(false);
			this->tabPage3->PerformLayout();
			this->tabPage4->ResumeLayout(false);
			this->tabPage4->PerformLayout();
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->EndInit();
			this->panel1->ResumeLayout(false);
			this->panel1->PerformLayout();
			this->ResumeLayout(false);

		}

		// Convert System::String^ to std::string without modifying the original string
		static void System2StdString(System::String^ s, std::string& os) {
			using namespace Runtime::InteropServices;
			const char* chars =
				(const char*)(Marshal::StringToHGlobalAnsi(s)).ToPointer();
			os = chars;
			Marshal::FreeHGlobal(IntPtr((void*)chars));
		}
#pragma endregion
		private: System::Void BrowseFile_Click(System::Object^ sender, System::EventArgs^ e)
		{
			openFileDialog1->InitialDirectory = Directory::GetCurrentDirectory();
			if (openFileDialog1->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				myStream = openFileDialog1->OpenFile();
				if ((myStream != nullptr))
				{
					strFileName = openFileDialog1->FileName;
					TextContent = File::ReadAllText(strFileName);
					TextBox->Text = File::ReadAllText(strFileName);
					displayLabel->Text = "A File is Chosen";
					myStream->Close();
				}
			}
		}
		private: System::Void TextBox_TextChanged(System::Object^ sender, System::EventArgs^ e)
		{
			TextContent = TextBox->Text;
		}
		private: System::Void AESEncrypt_Click(System::Object^ sender, System::EventArgs^ e)
		{
			msclr::interop::marshal_context context;
			std::string TextContentStr;
			if (TextContent != nullptr)
			{
				TextContentStr = context.marshal_as<std::string>(TextContent);
			}
			else
			{
				TextContentStr = "";
			}
			std::pair<std::string, bool> encrypt;
			encrypt = crypto->AESEncryptData(TextContentStr);
			if (encrypt.second == true)
			{
				this->displayLabel->ForeColor = System::Drawing::Color::DarkGreen;
				String^ EncryptedFileName = context.marshal_as<String^ >(crypto->getAESEncryptedFile());
				displayLabel->Text = "Encrypted " + EncryptedFileName;
			}
			else if (encrypt.second == false)
			{
				this->displayLabel->ForeColor = System::Drawing::Color::DarkRed;
				displayLabel->Text = "Error in Encryption";
			}
			TextContent = "";
			TextBox->Text = "";
		}
		private: System::Void AESDecrypt_Click(System::Object^ sender, System::EventArgs^ e)
		{
			openFileDialog1->InitialDirectory = Directory::GetCurrentDirectory();
			openFileDialog1->Filter = "Binary Files (*.bin)|*.bin|All Files (*.*)|*.*";

			if (openFileDialog1->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				myStream = openFileDialog1->OpenFile();
				if ((myStream != nullptr))
				{
					strFileName = openFileDialog1->FileName;
					msclr::interop::marshal_context context;
					std::string FileName;
					if (strFileName != nullptr)
					{
						FileName = context.marshal_as<std::string>(strFileName);
					}
					else
					{
						FileName = "";
					}
					std::pair<std::string, bool> decrypt;
					decrypt = crypto->AESDecryptFile(FileName);
					if (decrypt.second == true)
					{
						TextContent = context.marshal_as<String^ >(decrypt.first);
						TextBox->Text = TextContent;
						this->displayLabel->ForeColor = System::Drawing::Color::DarkGreen;
						String^ DecryptedFileName = context.marshal_as<String^ >(crypto->getAESDecryptedFile());
						displayLabel->Text = "Decrypted " + DecryptedFileName;
					}
					else if (decrypt.second == false)
					{
						TextContent = "";
						TextBox->Text = "";
						this->displayLabel->ForeColor = System::Drawing::Color::DarkRed;
						displayLabel->Text = "Error in Decryption";
					}
					myStream->Close();
				}
			}
		}

		private: System::Void button2_Click(System::Object^ sender, System::EventArgs^ e) {
			crypto->generateAESKey();
			this->displayLabel->ForeColor = System::Drawing::Color::DarkGreen;
			displayLabel->Text = "AES Key is Generated";
		}
		private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {
			crypto2->generateRSAKeys();
			this->displaylabel2->ForeColor = System::Drawing::Color::DarkGreen;
			displaylabel2->Text = "RSA Keys are Generated";
		}
		private: System::Void RSASign_Click(System::Object^ sender, System::EventArgs^ e) {
			msclr::interop::marshal_context context;
			std::string TextContentStr;
			if (TextContent != nullptr)
			{
				TextContentStr = context.marshal_as<std::string>(TextContent1);
			}
			else
			{
				TextContentStr = "";
			}
			std::pair<std::string, bool> encrypt;
			crypto1->RSASignData(TextContentStr);
			this->displaylabel1->ForeColor = System::Drawing::Color::DarkGreen;
			String^ EncryptedFileName = context.marshal_as<String^ >(crypto1->getRSASignature());
			displaylabel1->Text = "Signed " + EncryptedFileName;
			TextContent1 = "";
			TextBox1->Text = "";
		}
		private: System::Void RSAVerify_Click(System::Object^ sender, System::EventArgs^ e) {
			openFileDialog2->InitialDirectory = Directory::GetCurrentDirectory();
			openFileDialog2->Filter = "Binary Files (*.bin)|*.bin|All Files (*.*)|*.*";

			if (openFileDialog2->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				myStream1 = openFileDialog2->OpenFile();
				if ((myStream1 != nullptr))
				{
					strFileName1 = openFileDialog2->FileName;
					msclr::interop::marshal_context context;
					std::string FileName;
					if (strFileName1 != nullptr)
					{
						FileName = context.marshal_as<std::string>(strFileName1);
					}
					else
					{
						FileName = "";
					}
					bool verify = crypto1->RSAVerifyFile(FileName, crypto1->getPublicKeyPath());
					if (verify == true)
					{
						TextContent1 = "";
						TextBox1->Text = TextContent1;
						this->displaylabel1->ForeColor = System::Drawing::Color::DarkGreen;
						String^ DecryptedFileName = context.marshal_as<String^ >(crypto1->getRSAVerification());
						displaylabel1->Text = "Verified " + DecryptedFileName;
					}
					else if (verify == false)
					{
						TextContent1 = "";
						TextBox1->Text = "";
						this->displaylabel1->ForeColor = System::Drawing::Color::DarkRed;
						displaylabel1->Text = "Error in Verification";
					}
					myStream1->Close();
				}
			}
		}
		private: System::Void SignAndEncrypt_Click(System::Object^ sender, System::EventArgs^ e) {
			msclr::interop::marshal_context context;
			std::string TextContentStr;
			if (TextContent2 != nullptr)
			{
				TextContentStr = context.marshal_as<std::string>(TextContent2);
			}
			else
			{
				TextContentStr = "";
			}
			std::pair<std::string, bool> encrypt;
			encrypt = crypto2->SignAndEncryptData(TextContentStr);
			if (encrypt.second == true)
			{
				this->displaylabel2->ForeColor = System::Drawing::Color::DarkGreen;
				String^ EncryptedFileName = context.marshal_as<String^ >(crypto2->getEncrypted_SignedFile());
				displaylabel2->Text = "Signed And Encrypted " + EncryptedFileName;
			}
			else if (encrypt.second == false)
			{
				this->displaylabel2->ForeColor = System::Drawing::Color::DarkRed;
				displaylabel2->Text = context.marshal_as<String^ >(encrypt.first);
			}
			TextContent2 = "";
			TextBox2->Text = "";
		}
		private: System::Void DecryptAndVerify_Click(System::Object^ sender, System::EventArgs^ e) {
			openFileDialog3->InitialDirectory = Directory::GetCurrentDirectory();
			openFileDialog3->Filter = "Binary Files (*.bin)|*.bin|All Files (*.*)|*.*";

			if (openFileDialog3->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				myStream2 = openFileDialog3->OpenFile();
				if ((myStream2 != nullptr))
				{
					strFileName2 = openFileDialog3->FileName;
					msclr::interop::marshal_context context;
					std::string FileName;
					if (strFileName2 != nullptr)
					{
						FileName = context.marshal_as<std::string>(strFileName2);
					}
					else
					{
						FileName = "";
					}
					std::pair<std::string, bool> decrypt;
					decrypt = crypto2->DecryptAndVerifyFile(FileName, crypto2->getPublicKeyPath());
					if (decrypt.second == true)
					{
						TextContent2 = context.marshal_as<String^ >(decrypt.first);
						TextBox2->Text = TextContent2;
						this->displaylabel2->ForeColor = System::Drawing::Color::DarkGreen;
						String^ DecryptedFileName = context.marshal_as<String^ >(crypto2->getDecrypted_VerifiedFile());
						displaylabel2->Text = "Decrypted And Verified " + DecryptedFileName;
					}
					else if (decrypt.second == false)
					{
						TextContent2 = "";
						TextBox2->Text = "";
						this->displaylabel2->ForeColor = System::Drawing::Color::DarkRed;
						displaylabel2->Text = context.marshal_as<String^ >(decrypt.first);
					}
					myStream2->Close();
				}
			}
		}
		private: System::Void browsefile1_Click(System::Object^ sender, System::EventArgs^ e) {
			openFileDialog2->InitialDirectory = Directory::GetCurrentDirectory();
			if (openFileDialog2->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				myStream1 = openFileDialog2->OpenFile();
				if ((myStream1 != nullptr))
				{
					strFileName1 = openFileDialog2->FileName;
					TextContent1 = File::ReadAllText(strFileName);
					TextBox1->Text = File::ReadAllText(strFileName);
					displaylabel1->Text = "A File is Chosen";
					myStream1->Close();
				}
			}
		}
		private: System::Void browsefile2_Click(System::Object^ sender, System::EventArgs^ e) {
			openFileDialog3->InitialDirectory = Directory::GetCurrentDirectory();
			if (openFileDialog3->ShowDialog() == System::Windows::Forms::DialogResult::OK)
			{
				myStream2 = openFileDialog3->OpenFile();
				if ((myStream2 != nullptr))
				{
					strFileName2 = openFileDialog2->FileName;
					TextContent2 = File::ReadAllText(strFileName);
					TextBox2->Text = File::ReadAllText(strFileName);
					displaylabel2->Text = "A File is Chosen";
					myStream1->Close();
				}
			}
		}
		private: System::Void button4_Click(System::Object^ sender, System::EventArgs^ e) {
			crypto2->generateAESKey();
			this->displaylabel2->ForeColor = System::Drawing::Color::Green;
			displaylabel2->Text = "AES Key is Generated";
		}
		private: System::Void button6_Click(System::Object^ sender, System::EventArgs^ e) {
			crypto1->generateRSAKeys();
			this->displaylabel1->ForeColor = System::Drawing::Color::Green;
			displaylabel1->Text = "RSA Keys are Generated";
		}
		private: System::Void TextBox1_TextChanged(System::Object^ sender, System::EventArgs^ e) {
			TextContent1 = TextBox1->Text;
		}
		private: System::Void TextBox2_TextChanged(System::Object^ sender, System::EventArgs^ e) {
			TextContent2 = TextBox2->Text;
		}
		private: System::Void tabControl1_Click(System::Object^ sender, System::EventArgs^ e) {
			if (tabControl1->SelectedTab->Text == "AES")
			{
				label1->Text = "AES Encryption and Decryption";
			}
			else if(tabControl1->SelectedTab->Text == "Sign And Verify")
			{
				label1->Text = "Signing And Verification";
			}
			else if (tabControl1->SelectedTab->Text == "AES With Sign And Verify")
			{
				label1->Text = "AES With Signing And Verification";
			}
		}
		private: System::Void richTextBox2_TextChanged(System::Object^ sender, System::EventArgs^ e) {
			MessageClient1 = richTextBox2->Text;
		}
		private: System::Void richTextBox4_TextChanged(System::Object^ sender, System::EventArgs^ e) {
			MessageClient2 = richTextBox4->Text;
		}
		private: System::Void button3_Click(System::Object^ sender, System::EventArgs^ e) {
			msclr::interop::marshal_context context;
			publicClient1Key = context.marshal_as<String^ >(client1->getPublicKeyPath());
			publicClient2Key = context.marshal_as<String^ >(client2->getPublicKeyPath());
			richTextBox1->Text = "Connection Established...\r\n\r\n";
			richTextBox3->Text = "Connection Established...\r\n\r\n";
			connected = true;
		}
		private: System::Void clearmessages_Click(System::Object^ sender, System::EventArgs^ e) {
			richTextBox1->Text = "";
			richTextBox3->Text = "";
			connected = false;
		}

		private: System::Void sendmessageclient1_Click(System::Object^ sender, System::EventArgs^ e) {
			msclr::interop::marshal_context context;
			if (!connected)
			{
				publicClient1Key = context.marshal_as<String^ >(client1->getPublicKeyPath());
				publicClient2Key = context.marshal_as<String^ >(client2->getPublicKeyPath());
				richTextBox1->Text = "Connection Established...\r\n\r\n";
				richTextBox3->Text = "Connection Established...\r\n\r\n";
				connected = true;
			}
			std::string publicClient1KeyPath;
			if (publicClient1Key != nullptr)
			{
				publicClient1KeyPath = context.marshal_as<std::string>(publicClient1Key);
			}
			else
			{
				publicClient1KeyPath = "";
			}
			std::string message;
			if (MessageClient1 != nullptr)
			{
				message = context.marshal_as<std::string>(MessageClient1);
			}
			else
			{
				message = "";
			}
			richTextBox1->Text = richTextBox1->Text + "Client 1 : " +  context.marshal_as<String^ >(message) + "\r\n";
			std::pair<std::string, bool> encrypt = client1->SignAndEncryptData(message);
			if (encrypt.second == false)
			{
				return;
			}
			std::pair<std::string, bool> decrypt = client2->DecryptAndVerifyData(encrypt.first, publicClient1KeyPath);
			if (decrypt.second == false)
			{
				return;
			}
			else if (decrypt.second == true)
			{
				richTextBox3->Text = richTextBox3->Text + "Client 1 : "  + context.marshal_as<String^ >(decrypt.first) + "\r\n";
			}
			richTextBox2->Text = "";
		}
		private: System::Void sendmessageclient2_Click(System::Object^ sender, System::EventArgs^ e) {
			msclr::interop::marshal_context context;
			if (!connected)
			{
				publicClient1Key = context.marshal_as<String^ >(client1->getPublicKeyPath());
				publicClient2Key = context.marshal_as<String^ >(client2->getPublicKeyPath());
				richTextBox1->Text = "Connection Established...\r\n\r\n";
				richTextBox3->Text = "Connection Established...\r\n\r\n";
				connected = true;
			}
			std::string publicClient2KeyPath;
			if (publicClient2Key != nullptr)
			{
				publicClient2KeyPath = context.marshal_as<std::string>(publicClient2Key);
			}
			else
			{
				publicClient2KeyPath = "";
			}
			std::string message;
			if (MessageClient2 != nullptr)
			{
				message = context.marshal_as<std::string>(MessageClient2);
			}
			else
			{
				message = "";
			}
			richTextBox3->Text = richTextBox3->Text + "Client 2 : " + context.marshal_as<String^ >(message) + "\r\n";
			std::pair<std::string, bool> encrypt = client2->SignAndEncryptData(message);
			if (encrypt.second == false)
			{
				return;
			}
			std::pair<std::string, bool> decrypt = client1->DecryptAndVerifyData(encrypt.first, publicClient2KeyPath);
			if (decrypt.second == false)
			{
				return;
			}
			else if (decrypt.second == true)
			{
				richTextBox1->Text = richTextBox1->Text + "Client 2 : " + context.marshal_as<String^ >(decrypt.first) + "\r\n";
			}
			richTextBox4->Text = "";
		}
};
}
