unit unitDashboard;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.Objects, System.ImageList, FMX.ImgList,
  IdHTTP, IdSSLOpenSSL, System.JSON, System.net.HttpClient;

type
  TformDashboard = class(TForm)
    labelNama: TLabel;
    labelSelamat: TLabel;
    rectangleAtas: TRectangle;
    Image2: TImage;
    buttonBelanja: TImage;
    buttonKeranjang: TImage;
    buttonDataUser: TImage;
    buttonLogout: TImage;
    buttonInformation: TImage;
    imageSMKNJ: TImage;
    rectangleTengah: TRectangle;
    procedure FormCreate(Sender: TObject);
    procedure buttonBelanjaClick(Sender: TObject);
    procedure buttonKeranjangClick(Sender: TObject);
    procedure buttonDataUserClick(Sender: TObject);
    procedure buttonLogoutClick(Sender: TObject);
    procedure buttonInformationClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  formDashboard: TformDashboard;

implementation

{$R *.fmx}

uses
  unitGlobal, unitDataUser, unitBelanja, unitKeranjang, unitLogin;

procedure TformDashboard.buttonBelanjaClick(Sender: TObject);
begin
  formBelanja := TFormBelanja.Create(nil);
  formBelanja.Show;
end;

procedure TformDashboard.buttonDataUserClick(Sender: TObject);
begin
  formDataUser := TFormDataUser.Create(nil);
  formDataUser.Show;
end;

procedure TformDashboard.buttonInformationClick(Sender: TObject);
begin
  ShowMessage('Mellee - Aplikasi Belanja SMKNJ Versi 1.0');
end;

procedure TformDashboard.buttonKeranjangClick(Sender: TObject);
begin
  formKeranjang := TFormKeranjang.Create(nil);
  formKeranjang.Show;
end;

procedure TformDashboard.buttonLogoutClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  Response: string;
  JSON: TStringStream;
  JSONObj: TJSONObject;
begin
  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
    JSON := TStringStream.Create('{}', TEncoding.UTF8);
    try
//      Response := IdHTTP.Post('http://localhost/api_penjualan/api.php?type=handleLogout', JSON);
      Response := IdHTTP.Post(server + 'api_penjualan/api.php?type=handleLogout', JSON);
      JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
      if JSONObj <> nil then
      try
        ShowMessage(JSONObj.GetValue<string>('message'));
        globalToken := '';
        formLogin := TFormLogin.Create(nil);
        formDashboard.hide;
        formLogin.Show;
      finally
        JSONObj.Free;
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Logout failed: ' + E.Message);
  end;
  IdHTTP.Free;
end;

procedure TformDashboard.FormCreate(Sender: TObject);
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
      labelNama.Text := JSONObj.GetValue<string>('nama');
    finally
      JSONObj.Free;
    end;
  except
    on E: Exception do

  end;
  IdHTTP.Free;
end;

end.
