unit unitLogin;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  FMX.Controls.Presentation, FMX.StdCtrls, FMX.Edit, FMX.Objects, FMX.Effects,
  System.ImageList, FMX.ImgList, IdHTTP, IdSSLOpenSSL, System.JSON, System.net.HttpClient,
  FMX.Layouts;

type
  TformLogin = class(TForm)
    btLogin: TImage;
    buttonRegister: TLabel;
    editPassword: TEdit;
    editUsername: TEdit;
    imageLogo: TImage;
    textLogin: TLabel;
    procedure btLoginClick(Sender: TObject);
    procedure buttonRegisterClick(Sender: TObject);
  private
    { Private declarations }
    var

  public
    { Public declarations }
  end;

var
  formLogin: TformLogin;

implementation

{$R *.fmx}
{$R *.LgXhdpiTb.fmx ANDROID}

uses
  unitDashboard, unitGlobal, unitRegister;

procedure TformLogin.btLoginClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  SSL: TIdSSLIOHandlerSocketOpenSSL;
  Response: string;
  JSON: TStringStream;
  username, password, pesanJSON: string;

  JSONObj: TJSONObject;
begin
  username := editUsername.Text;
  password := editPassword.Text;
  IdHTTP := TIdHTTP.Create(nil);
  SSL := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  try
    JSON := TStringStream.Create(
      '{"username":"' + username + '","password":"' + password + '"}',
      TEncoding.UTF8);
    try
//      Response := IdHTTP.Post('http://localhost/api_penjualan/api.php?type=handleLogin', JSON);
      Response := IdHTTP.Post(server + 'api_penjualan/api.php?type=handleLogin', JSON);
      JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
      if JSONObj <> nil then
      try
        pesanJSON := JSONObj.GetValue<string>('message');
        if pesanJSON = 'Login successful' then
        begin
          globalToken := JSONObj.GetValue<string>('token');
          ShowMessage('Login Berhasil!');
          formDashboard := TFormDashboard.Create(nil);
          formLogin.Hide;
          formDashboard.Show;
        end
        else
          ShowMessage('Login Gagal: ' + pesanJSON);
          editUsername.Text := '';
          editPassword.Text := '';
          editUsername.SetFocus;
      finally
        JSONObj.Free;
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Login Gagal!');
  end;

  IdHTTP.Free;
  SSL.Free;
  editUsername.Text := '';
  editPassword.Text := '';
end;

procedure TformLogin.buttonRegisterClick(Sender: TObject);
begin
  formRegister := TFormRegister.Create(nil);
  formRegister.Show;
end;

end.
