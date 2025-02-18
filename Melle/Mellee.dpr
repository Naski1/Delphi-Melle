program Mellee;

uses
  System.StartUpCopy,
  FMX.Forms,
  unitLogin in 'unitLogin.pas' {formLogin},
  unitDashboard in 'unitDashboard.pas' {formDashboard},
  unitDataUser in 'unitDataUser.pas' {formDataUser},
  unitRegister in 'unitRegister.pas' {formRegister},
  unitKeranjang in 'unitKeranjang.pas' {formKeranjang},
  unitBelanja in 'unitBelanja.pas' {Form1},
  unitGlobal in 'unitGlobal.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.FormFactor.Orientations := [TFormOrientation.Portrait];
  Application.CreateForm(TformLogin, formLogin);
  Application.CreateForm(TformDashboard, formDashboard);
  Application.CreateForm(TformDataUser, formDataUser);
  Application.CreateForm(TformRegister, formRegister);
  Application.CreateForm(TformKeranjang, formKeranjang);
  Application.CreateForm(TformBelanja, formBelanja);
  Application.Run;
end.
