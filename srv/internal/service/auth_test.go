package service

import "testing"

func TestEnvironmentAuthenticationAndSession(t *testing.T) {
	service, err := NewAuthService("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, authenticated, err := service.Login("admin", "wrong"); err != nil {
		t.Fatal(err)
	} else if authenticated {
		t.Fatal("wrong password authenticated")
	}

	token, user, authenticated, err := service.Login("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !authenticated || user.Username != "admin" || token == "" {
		t.Fatalf("unexpected login result: authenticated=%v user=%#v", authenticated, user)
	}
	if sessionUser, valid := service.Session(token); !valid || sessionUser != user {
		t.Fatalf("session user = %#v, valid=%v", sessionUser, valid)
	}
	service.Logout(token)
	if _, valid := service.Session(token); valid {
		t.Fatal("logged out session remained valid")
	}
}
