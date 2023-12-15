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

	Crypto::CryptoClient* crypto;

	public:
		SecurityForm(void)
		{
			InitializeComponent();
			//
			//TODO: Add the constructor code here
			//
			AES::AESKey::generateKey();
			crypto = new Crypto::CryptoClient("Crypto");
			displayLabel->Text = "";
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
			this->SuspendLayout();
			// 
			// displayLabel
			// 
			this->displayLabel->AutoSize = true;
			this->displayLabel->Font = (gcnew System::Drawing::Font(L"Times New Roman", 13.8F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->displayLabel->Location = System::Drawing::Point(7, 470);
			this->displayLabel->Name = L"displayLabel";
			this->displayLabel->Size = System::Drawing::Size(80, 25);
			this->displayLabel->TabIndex = 0;
			this->displayLabel->Text = L"display";
			// 
			// AESEncrypt
			// 
			this->AESEncrypt->Location = System::Drawing::Point(351, 428);
			this->AESEncrypt->Name = L"AESEncrypt";
			this->AESEncrypt->Size = System::Drawing::Size(100, 31);
			this->AESEncrypt->TabIndex = 1;
			this->AESEncrypt->Text = L"AES Encrypt";
			this->AESEncrypt->UseVisualStyleBackColor = true;
			this->AESEncrypt->Click += gcnew System::EventHandler(this, &SecurityForm::AESEncrypt_Click);
			// 
			// AESDecrypt
			// 
			this->AESDecrypt->Location = System::Drawing::Point(457, 428);
			this->AESDecrypt->Name = L"AESDecrypt";
			this->AESDecrypt->Size = System::Drawing::Size(100, 31);
			this->AESDecrypt->TabIndex = 2;
			this->AESDecrypt->Text = L"AES Decrypt";
			this->AESDecrypt->UseVisualStyleBackColor = true;
			this->AESDecrypt->Click += gcnew System::EventHandler(this, &SecurityForm::AESDecrypt_Click);
			// 
			// RSASign
			// 
			this->RSASign->Location = System::Drawing::Point(563, 428);
			this->RSASign->Name = L"RSASign";
			this->RSASign->Size = System::Drawing::Size(100, 31);
			this->RSASign->TabIndex = 3;
			this->RSASign->Text = L"RSA Sign";
			this->RSASign->UseVisualStyleBackColor = true;
			this->RSASign->Click += gcnew System::EventHandler(this, &SecurityForm::RSASign_Click);
			// 
			// RSAVerify
			// 
			this->RSAVerify->Location = System::Drawing::Point(669, 428);
			this->RSAVerify->Name = L"RSAVerify";
			this->RSAVerify->Size = System::Drawing::Size(100, 31);
			this->RSAVerify->TabIndex = 4;
			this->RSAVerify->Text = L"RSA Verify";
			this->RSAVerify->UseVisualStyleBackColor = true;
			this->RSAVerify->Click += gcnew System::EventHandler(this, &SecurityForm::RSAVerify_Click);
			// 
			// SignAndEncrypt
			// 
			this->SignAndEncrypt->Location = System::Drawing::Point(775, 428);
			this->SignAndEncrypt->Name = L"SignAndEncrypt";
			this->SignAndEncrypt->Size = System::Drawing::Size(123, 31);
			this->SignAndEncrypt->TabIndex = 5;
			this->SignAndEncrypt->Text = L"Sign And Encrypt";
			this->SignAndEncrypt->UseVisualStyleBackColor = true;
			this->SignAndEncrypt->Click += gcnew System::EventHandler(this, &SecurityForm::SignAndEncrypt_Click);
			// 
			// DecryptAndVerify
			// 
			this->DecryptAndVerify->Location = System::Drawing::Point(904, 428);
			this->DecryptAndVerify->Name = L"DecryptAndVerify";
			this->DecryptAndVerify->Size = System::Drawing::Size(123, 31);
			this->DecryptAndVerify->TabIndex = 6;
			this->DecryptAndVerify->Text = L"Decrypt And Verify";
			this->DecryptAndVerify->UseVisualStyleBackColor = true;
			this->DecryptAndVerify->Click += gcnew System::EventHandler(this, &SecurityForm::DecryptAndVerify_Click);
			// 
			// BrowseFile
			// 
			this->BrowseFile->Location = System::Drawing::Point(1038, 428);
			this->BrowseFile->Name = L"BrowseFile";
			this->BrowseFile->Size = System::Drawing::Size(100, 31);
			this->BrowseFile->TabIndex = 7;
			this->BrowseFile->Text = L"Browse File";
			this->BrowseFile->UseVisualStyleBackColor = true;
			this->BrowseFile->Click += gcnew System::EventHandler(this, &SecurityForm::BrowseFile_Click);
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(129, 428);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(123, 31);
			this->button1->TabIndex = 8;
			this->button1->Text = L"Generate RSA Keys";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &SecurityForm::button1_Click);
			// 
			// button2
			// 
			this->button2->Location = System::Drawing::Point(0, 428);
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
			this->TextBox->Location = System::Drawing::Point(12, 12);
			this->TextBox->Name = L"TextBox";
			this->TextBox->Size = System::Drawing::Size(1126, 410);
			this->TextBox->TabIndex = 10;
			this->TextBox->Text = L"";
			this->TextBox->TextChanged += gcnew System::EventHandler(this, &SecurityForm::TextBox_TextChanged);
			// 
			// openFileDialog1
			// 
			this->openFileDialog1->FileName = L"openFileDialog1";
			// 
			// SecurityForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(1150, 513);
			this->Controls->Add(this->TextBox);
			this->Controls->Add(this->button2);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->BrowseFile);
			this->Controls->Add(this->DecryptAndVerify);
			this->Controls->Add(this->SignAndEncrypt);
			this->Controls->Add(this->RSAVerify);
			this->Controls->Add(this->RSASign);
			this->Controls->Add(this->AESDecrypt);
			this->Controls->Add(this->AESEncrypt);
			this->Controls->Add(this->displayLabel);
			this->Margin = System::Windows::Forms::Padding(2);
			this->Name = L"SecurityForm";
			this->Text = L"SecurityForm";
			this->ResumeLayout(false);
			this->PerformLayout();

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
			this->displayLabel->ForeColor = System::Drawing::Color::Green;
			String^ EncryptedFileName = context.marshal_as<String^ >(crypto->getAESEncryptedFile());
			displayLabel->Text = "Encrypted " + EncryptedFileName;
		}
		else if (encrypt.second == false)
		{
			this->displayLabel->ForeColor = System::Drawing::Color::Red;
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
					this->displayLabel->ForeColor = System::Drawing::Color::Green;
					String^ DecryptedFileName = context.marshal_as<String^ >(crypto->getAESDecryptedFile());
					displayLabel->Text = "Decrypted " + DecryptedFileName;
				}
				else if (decrypt.second == false)
				{
					TextContent = "";
					TextBox->Text = "";
					this->displayLabel->ForeColor = System::Drawing::Color::Red;
					displayLabel->Text = "Error in Decryption";
				}
				myStream->Close();
			}
		}
	}

	private: System::Void button2_Click(System::Object^ sender, System::EventArgs^ e) {
		crypto->generateAESKey();
		this->displayLabel->ForeColor = System::Drawing::Color::Green;
		displayLabel->Text = "AES Key is Generated";
	}
	private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {
		crypto->generateRSAKeys();
		this->displayLabel->ForeColor = System::Drawing::Color::Green;
		displayLabel->Text = "RSA Keys are Generated";
	}
	private: System::Void RSASign_Click(System::Object^ sender, System::EventArgs^ e) {
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
		crypto->RSASignData(TextContentStr, crypto->getPrivateKeyPath());
		this->displayLabel->ForeColor = System::Drawing::Color::Green;
		String^ EncryptedFileName = context.marshal_as<String^ >(crypto->getRSASignature());
		displayLabel->Text = "Signed " + EncryptedFileName;
		TextContent = "";
		TextBox->Text = "";
	}
	private: System::Void RSAVerify_Click(System::Object^ sender, System::EventArgs^ e) {
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
				bool verify = crypto->RSAVerifyFile(FileName, crypto->getPublicKeyPath());
				if (verify == true)
				{
					TextContent = "";
					TextBox->Text = TextContent;
					this->displayLabel->ForeColor = System::Drawing::Color::Green;
					String^ DecryptedFileName = context.marshal_as<String^ >(crypto->getRSAVerification());
					displayLabel->Text = "Verified " + DecryptedFileName;
				}
				else if (verify == false)
				{
					TextContent = "";
					TextBox->Text = "";
					this->displayLabel->ForeColor = System::Drawing::Color::Red;
					displayLabel->Text = "Error in Verification";
				}
				myStream->Close();
			}
		}
	}
	private: System::Void SignAndEncrypt_Click(System::Object^ sender, System::EventArgs^ e) {
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
		encrypt = crypto->SignAndEncryptData(TextContentStr, crypto->getPrivateKeyPath());
		if (encrypt.second == true)
		{
			this->displayLabel->ForeColor = System::Drawing::Color::Green;
			String^ EncryptedFileName = context.marshal_as<String^ >(crypto->getEncrypted_SignedFile());
			displayLabel->Text = "Signed And Encrypted " + EncryptedFileName;
		}
		else if (encrypt.second == false)
		{
			this->displayLabel->ForeColor = System::Drawing::Color::Red;
			displayLabel->Text = context.marshal_as<String^ >(encrypt.first);
		}
		TextContent = "";
		TextBox->Text = "";
	}
	private: System::Void DecryptAndVerify_Click(System::Object^ sender, System::EventArgs^ e) {
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
				decrypt = crypto->DecryptAndVerifyFile(FileName, crypto->getPublicKeyPath());
				if (decrypt.second == true)
				{
					TextContent = context.marshal_as<String^ >(decrypt.first);
					TextBox->Text = TextContent;
					this->displayLabel->ForeColor = System::Drawing::Color::Green;
					String^ DecryptedFileName = context.marshal_as<String^ >(crypto->getDecrypted_VerifiedFile());
					displayLabel->Text = "Decrypted And Verified " + DecryptedFileName;
				}
				else if (decrypt.second == false)
				{
					TextContent = "";
					TextBox->Text = "";
					this->displayLabel->ForeColor = System::Drawing::Color::Red;
					displayLabel->Text = context.marshal_as<String^ >(decrypt.first);
				}
				myStream->Close();
			}
		}
	}
};
}
