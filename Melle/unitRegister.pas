unit unitRegister;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  FMX.Controls.Presentation, FMX.StdCtrls, FMX.Objects, FMX.Effects, FMX.Edit,
  System.ImageList, FMX.ImgList, IdHTTP, IdSSLOpenSSL, System.JSON, System.net.HttpClient;

type
  TformRegister = class(TForm)
    kotakAtas: TRectangle;
    labelRegister: TLabel;
    imageLogo: TImage;
    buttonRegister: TImage;
    editUsername: TEdit;
    editPassword: TEdit;
    editNama: TEdit;
    editAlamat: TEdit;
    procedure buttonRegisterClick(Sender: TObject);
    
  private
    { Private declarations }

  public
    { Public declarations }
  end;

var
  formRegister: TformRegister;

implementation

{$R *.fmx}
uses
  unitLogin, unitGlobal;

procedure TformRegister.buttonRegisterClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  JSON: TStringStream;
  Response: string;
  username, password, nama, alamat, pesanJSON: string;
  JSONObj: TJSONObject;
begin
  username := editUsername.Text;
  password := editPassword.Text;
  nama := editNama.Text;
  alamat := editAlamat.Text;

  if (username = '') or (password = '') or (nama = '') or (alamat = '') then
  begin
    ShowMessage('Cek kembali isian anda, field dilarang kosong!');
    Exit;
  end;

  IdHTTP := TIdHTTP.Create(nil);
  try
    JSON := TStringStream.Create(
      '{"username":"' + username + '","password":"' + password + '","nama":"' + nama + '","alamat":"' + alamat + '"}',
      TEncoding.UTF8);
    try
//      Response := IdHTTP.Post('http://localhost/api_penjualan/api.php?type=handleRegister', JSON);
      Response := IdHTTP.Post(server + 'api_penjualan/api.php?type=handleRegister', JSON);
      JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
      if JSONObj <> nil then
      try
        pesanJSON := JSONObj.GetValue<string>('message');
        if pesanJSON = 'Registration successful' then
        begin
          ShowMessage('Registrasi Berhasil!');
          formLogin := TFormLogin.Create(nil);
          formRegister.Hide;
          formLogin.Show;
        end

        else if pesanJSON = 'Username already exists' then
        begin
          ShowMessage('Username sudah digunakan, silahkan gunakan username lain!');
          editUsername.Text := '';
          editUsername.SetFocus;
        end

        else
          ShowMessage('Registrasi Gagal: ' + pesanJSON);


      finally
        JSONObj.Free;
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Register failed: ' + E.Message);
  end;
  IdHTTP.Free;
end;

end.
