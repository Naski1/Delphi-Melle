unit unitKeranjang;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes, System.Variants,
  FMX.Types, FMX.Platform, FMX.WebBrowser, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.Objects,
  FMX.Controls.Presentation, FMX.StdCtrls, FMX.Layouts, FMX.ListBox,
  IdHTTP, IdSSLOpenSSL, System.JSON, System.net.HttpClient,
//  Androidapi.JNI.JavaTypes, Androidapi.JNI.App, FMX.Platform.Android, Androidapi.Helpers, Androidapi.JNI.Net, Androidapi.JNI.GraphicsContentViewText;
  ShellAPI, Windows;

type
  TKeranjangTag = class
    id_keranjang: Integer;
    jumlah: Integer;
  end;

  TformKeranjang = class(TForm)
    layoutData: TLayout;
    labelNama: TLabel;
    buttonTambah: TImage;
    buttonHapus: TImage;
    labelSubtotal: TLabel;
    labelJumlah: TLabel;
    buttonKurang: TImage;
    rectangleAtas: TRectangle;
    labelKeranjang: TLabel;
    imageIcon: TImage;
    listBoxData: TListBox;
    labelTotal: TLabel;
    buttonCheckout: TImage;
    rectangleBawah: TRectangle;
    labelTotalKeranjang: TLabel;
    procedure buttonHapusClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure buttonTambahClick(Sender: TObject);
    procedure buttonKurangClick(Sender: TObject);
    procedure buttonCheckoutClick(Sender: TObject);
  private
    var
      total : Integer;
    { Private declarations }
    procedure TampilList(IsiJSON: string);
    procedure addItem(nama_produk: string; subtotal, jumlah, id_keranjang : integer);
    procedure LoadCartData;
  public
    { Public declarations }
  end;

var
  formKeranjang: TformKeranjang;

implementation

{$R *.fmx}

uses
  unitGlobal;

function FormatRupiah(Harga: Integer): string;
begin
  Result := 'Rp. ' + FormatFloat('#,##0', Harga) + ',-';
end;

procedure TformKeranjang.LoadCartData;
var
  IdHTTP: TIdHTTP;
  SSL: TIdSSLIOHandlerSocketOpenSSL;
  Response: string;
begin
  listBoxData.Items.Clear;
  IdHTTP := TIdHTTP.Create(nil);
  SSL := TIdSSLIOHandlerSocketOpenSSL.Create(nil);

  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
//    Response := IdHTTP.Get('http://localhost/api_penjualan/api.php?type=cartItem');
    Response := IdHTTP.Get(server + 'api_penjualan/api.php?type=cartItem');
    TampilList(Response);
  except
    on E: Exception do

  end;
  IdHTTP.Free;
  SSL.Free;
end;

procedure TformKeranjang.buttonCheckoutClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  Response: string;
  JSONValue: TJSONArray;
  JSONItem: TJSONObject;
  penggunaNama, penggunaAlamat: string;
  nama_produk: string;
  harga, jumlah, subtotal, total: Integer;
  i: Integer;
  urlWhatsApp: String;
//  Intent: JIntent;
begin
  // Ambil data pengguna
  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
//    Response := IdHTTP.Get('http://localhost/api_penjualan/api.php?type=userProfile');
    Response := IdHTTP.Get(server + 'api_penjualan/api.php?type=userProfile');
    JSONItem := TJSONObject.ParseJSONValue(Response) as TJSONObject;

    if Assigned(JSONItem) then
    begin
      penggunaNama := JSONItem.GetValue<string>('nama');
      penggunaAlamat := JSONItem.GetValue<string>('alamat');
      JSONItem.Free;
    end;
  finally
    IdHTTP.Free;
  end;

  // Menyusun pesan WhatsApp awal
  urlWhatsApp := 'https://wa.me/6281939700093?text=' +
                 'Halo, saya ' + penggunaNama + '%0A' +
                 'Alamat: ' + penggunaAlamat + '%0A' +
                 'Saya ingin membeli: %0A' +
                 '----------------------------------%0A';

  // Ambil data keranjang dari API
  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
//    Response := IdHTTP.Get('http://localhost/api_penjualan/api.php?type=cartItem');
    Response := IdHTTP.Get(server + 'api_penjualan/api.php?type=cartItem');
    JSONValue := TJSONObject.ParseJSONValue(Response) as TJSONArray;

    total := 0;
    if Assigned(JSONValue) then
    begin
      for i := 0 to JSONValue.Count - 1 do
      begin
        JSONItem := JSONValue.Items[i] as TJSONObject;
        nama_produk := JSONItem.GetValue<string>('nama_produk');
        harga := JSONItem.GetValue<Integer>('harga');
        jumlah := JSONItem.GetValue<Integer>('jumlah');
        subtotal := harga * jumlah;
        total := total + subtotal;

        // Tambahkan produk ke pesan WhatsApp
        urlWhatsApp := urlWhatsApp +
                       nama_produk + '%0A' +
                       'Harga: ' + FormatRupiah(harga) + '%0A' +
                       'Jumlah: ' + jumlah.ToString + '%0A' +
                       'Subtotal: ' + FormatRupiah(subtotal) + '%0A' +
                       '----------------------------------%0A';
      end;

      // Tambahkan total
      urlWhatsApp := urlWhatsApp + 'Total: ' + FormatRupiah(total) + '%0A';
    end;
  finally
    IdHTTP.Free;
  end;

//  Intent := TJIntent.JavaClass.init(TJIntent.JavaClass.ACTION_VIEW,
//            TJnet_Uri.JavaClass.parse(StringToJString(urlWhatsApp)));

//  TAndroidHelper.Activity.startActivity(Intent);

  ShellExecute(0, 'open', PChar(urlWhatsApp), nil, nil, SW_SHOWNORMAL);
end;

procedure TformKeranjang.buttonHapusClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  Response: string;
  id_keranjang: Integer;
  JSON: TStringStream;
  JSONObj: TJSONObject;
begin
  id_keranjang := (Sender as TImage).Tag;
  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
    try
//      Response := IdHTTP.Delete('http://localhost/api_penjualan/api.php?type=cartItem&id_keranjang=' + id_keranjang.ToString);
      Response := IdHTTP.Delete(server + 'api_penjualan/api.php?type=cartItem&id_keranjang=' + id_keranjang.ToString);
      JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
      if JSONObj <> nil then
      try
        ShowMessage(JSONObj.GetValue<string>('message'));
        LoadCartData;
      finally
        JSONObj.Free;
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Failed to remove: ' + E.Message);
  end;
  IdHTTP.Free;
end;

procedure TformKeranjang.buttonKurangClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  JSON: TStringStream;
  Response: string;
  JSONObj: TJSONObject;
  id_keranjang: Integer;
  newJumlah: Integer;
  parentLayout: TLayout;
  labelJumlahClone: TLabel;
  keranjangItem: TKeranjangTag;
begin
  keranjangItem := TKeranjangTag((Sender as TImage).Tag);
  id_keranjang := keranjangItem.id_keranjang;
  newJumlah := keranjangItem.jumlah - 1;
  if newJumlah < 1 then
    begin
      ShowMessage('Jumlah tidak boleh kurang dari 1!');
      Exit;
    end;

  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
    JSON := TStringStream.Create(
      '{"id_keranjang":"' + id_keranjang.ToString + '","jumlah":"' + newJumlah.ToString + '"}', TEncoding.UTF8);
    try
//      Response := IdHTTP.Put('http://localhost/api_penjualan/api.php?type=cartItem', JSON);
      Response := IdHTTP.Put(server + 'api_penjualan/api.php?type=cartItem', JSON);
      JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
      if JSONObj <> nil then
      try
        ShowMessage(JSONObj.GetValue<string>('message'));
        LoadCartData;
      finally
        JSONObj.Free;
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Failed to update cart: ' + E.Message);
  end;
  IdHTTP.Free;
end;

procedure TformKeranjang.buttonTambahClick(Sender: TObject);
var
  IdHTTP: TIdHTTP;
  JSON: TStringStream;
  Response: string;
  JSONObj: TJSONObject;
  id_keranjang: Integer;
  newJumlah: Integer;
  parentLayout: TLayout;
  labelJumlahClone: TLabel;
  keranjangItem: TKeranjangTag;
begin
  keranjangItem := TKeranjangTag((Sender as TImage).Tag);
  id_keranjang := keranjangItem.id_keranjang;
  newJumlah := keranjangItem.jumlah + 1;

  IdHTTP := TIdHTTP.Create(nil);
  try
    IdHTTP.Request.CustomHeaders.AddValue('Authorization', globalToken);
    JSON := TStringStream.Create(
      '{"id_keranjang":"' + id_keranjang.ToString + '","jumlah":"' + newJumlah.ToString + '"}', TEncoding.UTF8);
    try
//      Response := IdHTTP.Put('http://localhost/api_penjualan/api.php?type=cartItem', JSON);
      Response := IdHTTP.Put(server + 'api_penjualan/api.php?type=cartItem', JSON);
      JSONObj := TJSONObject.ParseJSONValue(Response) as TJSONObject;
      if JSONObj <> nil then
      try
        ShowMessage(JSONObj.GetValue<string>('message'));
        LoadCartData;
      finally
        JSONObj.Free;
      end;
    finally
      JSON.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Failed to update cart: ' + E.Message);
  end;
  IdHTTP.Free;
end;

procedure TformKeranjang.FormCreate(Sender: TObject);
begin
  LoadCartData;
  layoutData.Visible := False;
end;

procedure TformKeranjang.TampilList(IsiJSON: string);
var
  JSONValue: TJSONArray;
  JSONItem: TJSONObject;
  i   : integer;
  id_keranjang, harga, jumlah, subtotal: integer;
  nama_produk : string;
  JSONList : TStringList;
begin
  listBoxData.Clear;
  JSONList := TStringList.Create;
  total := 0;
  try
    JSONValue := TJSONObject.ParseJSONValue(IsiJSON) as TJSONArray;

    if Assigned(JSONValue) then
    begin
      for i := 0 to JSONValue.Count - 1 do
      begin
        JSONItem := JSONValue.Items[i] as TJSONObject;
        nama_produk    := JSONItem.GetValue<string>('nama_produk');
        harga          := JSONItem.GetValue<Integer>('harga');
        jumlah         := JSONItem.GetValue<Integer>('jumlah');
        id_keranjang   := JSONItem.GetValue<Integer>('id_keranjang');
        subtotal := harga * jumlah;
        total := total + subtotal;
        addItem(nama_produk, subtotal, jumlah, id_keranjang);
      end;
      if total = 0 then
        buttonCheckout.Enabled := false;
      labelTotal.Text := FormatRupiah(total);
    end;
  except
    on E: Exception do
//      ShowMessage('Error: ' + E.Message);
  end;
  JSONList.Free;
end;

procedure TformKeranjang.addItem(nama_produk: string; subtotal, jumlah, id_keranjang : integer);
var
  loClone : TLayout;
  lb : TListBoxItem;
  buttonHapusClone, buttonTambahClone, buttonKurangClone : TImage;
  keranjangItem: TKeranjangTag;
begin
  labelNama.Text := nama_produk;
  labelSubtotal.Text := FormatRupiah(subtotal);
  labelJumlah.Text := jumlah.ToString;

  lb := TListBoxItem.Create(listBoxData);
  lb.Width := listBoxData.Width;
  lb.Height := layoutData.Height;
  lb.Selectable := false;

  loClone := TLayout(layoutData.Clone(lb));
  loClone.Width := lb.Width - 32;
  loClone.Position.X := 5;
  loClone.Position.Y := 0;
  loClone.Visible := true;

  buttonHapusClone := TImage(buttonHapus.Clone(loClone));
  buttonHapusClone.Parent := loClone;
  buttonHapusClone.Tag := id_keranjang;
  buttonHapusClone.OnClick := buttonHapusClick;

  keranjangItem := TKeranjangTag.Create;
  keranjangItem.id_keranjang := id_keranjang;
  keranjangItem.jumlah := jumlah;

  buttonTambahClone := TImage(buttonTambah.Clone(loClone));
  buttonTambahClone.Parent := loClone;
  buttonTambahClone.Tag := NativeInt(keranjangItem);
  buttonTambahClone.OnClick := buttonTambahClick;

  buttonKurangClone := TImage(buttonKurang.Clone(loClone));
  buttonKurangClone.Parent := loClone;
  buttonKurangClone.Tag := NativeInt(keranjangItem);
  buttonKurangClone.OnClick := buttonKurangClick;

  lb.AddObject(loClone);
  listBoxData.AddObject(lb);
end;
end.
