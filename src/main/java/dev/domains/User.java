package dev.domains;

public class User {

    private Integer id;
    private String login;
    private String firstname;
    private String lastname;
    private String password;
    private Boolean isAdmin;


    public User(Integer id, String firstname, String lastname, String password) {
        this(id, firstname, lastname);
        this.password = password;
    }

    public User(Integer id, String firstname, String lastname) {
        this(firstname, lastname);
        this.id = id;
    }

    public User(String firstname, String lastname) {
        this.firstname = firstname;
        this.lastname = lastname;
    }

    public User(String firstname, String lastname, String password) {
        this(firstname, lastname);
        this.password = password;
    }

    public User(String firstname, String lastname, String login, String password) {
        this(firstname, lastname, password);
        this.login = login;
    }

    public User(Integer id, String firstname, String lastname, String login, String password, Boolean isAdmin) {
        this(id, firstname, lastname, password);
        this.login = login;
        this.isAdmin =isAdmin;
    }

    public User() {

    }

    public Boolean getAdmin() {
        return isAdmin;
    }

    public void setAdmin(Boolean admin) {
        isAdmin = admin;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }


    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", login='" + login + '\'' +
                ", firstname='" + firstname + '\'' +
                ", lastname='" + lastname + '\'' +
                ", password='" + password + '\'' +
                ", isAdmin=" + isAdmin +
                '}';
    }
}
