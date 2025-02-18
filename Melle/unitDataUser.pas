unit unitDataUser;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs,
  FMX.Controls.Presentation, FMX.StdCtrls, FMX.Objects, FMX.Layouts, FMX.ListBox,
  IdHTTP, IdSSLOpenSSL, System.JSON, System.net.HttpClient, FMX.Edit;

type
  TformDataUser = class(TForm)
    Label3: TLabel;
    Image2: TImage;
    editUsername: TEdit;
    editPasswordLama: TEdit;
    editNama: TEdit;
    editAlamat: TEdit;
    buttonUpdateData: TImage;
    editPasswordBaru: TEdit;
    procedure FormCreate(Sender: TObject);
    procedure buttonUpdateDataClick(Sender: TObject);

  private
    { Private declarations }

  public
    { Public declarations }
  end;

var
  formDataUser: TformDataUser;

implementation

{$R *.fmx}
uses
  unitGlobal, unitLogin, unitDashboard;

procedure TformDataUser.buttonUpdateDataClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  JSON: TStringStream;
  Response: string;
  JSONObj: TJSONObject;
  nama, alamat, username, current_password, new_password, pesanJSON: string;
begin
  nama := editNama.Text;
  alamat := editAlamat.Text;
  username := editUsername.Text;
  current_password := editPasswordLama.Text;
  new_password := editPasswordBaru.Text;

  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
    JSON := TStringStream.Create(
      '{"nama":"' + nama
      + '","alamat":"' + alamat
      + '","username":"' + username
      + '","current_password":"' + current_password
      + '","new_password":"' + new_password + '"}'
      , TEncoding.UTF8);
    try
//      Response := IdHTTP.Put('http://localhost/api_penjualan/api.php?type=userProfile', JSON);
      Response := IdHTTP.Put(server + 'api_penjualan/api.php?type=userProfile', JSON);
      JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
      if JSONObj <> nil then
      try
      pesanJSON := JSONObj.GetValue<string>('message');
      ShowMessage(pesanJSON);
      editPasswordLama.Text := '';
      editPasswordBaru.Text := '';
      finally
        JSONObj.Free;
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Failed to update profile: ' + E.Message);
  end;
  IdHTTP.Free;
end;

procedure TformDataUser.FormCreate(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  Response: string;
  JSONObj: TJSONObject;
begin
  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
//    Response := IdHTTP.Get('http://localhost/api_penjualan/api.php?type=userProfile');
    Response := IdHTTP.Get(server + 'api_penjualan/api.php?type=userProfile');
    JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
    if JSONObj <> nil then
    try
      editUsername.Text := JSONObj.GetValue<string>('username');
      editNama.Text := JSONObj.GetValue<string>('nama');
      editAlamat.Text := JSONObj.GetValue<string>('alamat');
    finally
      JSONObj.Free;
    end;
  except
    on E: Exception do

  end;
  IdHTTP.Free;
end;

end.
