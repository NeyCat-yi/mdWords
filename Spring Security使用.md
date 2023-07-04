# Spring Security使用

### 1、导入依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### 2、基础使用

（1）实现UserDetailsService接口，输入用户名密码时与数据库做校验

```java
@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    UserDao dao;

    /**
    	s：用户名
    **/
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        //查询用户信息

        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUsername,s);
        User user = dao.selectOne(queryWrapper);

        if (Objects.isNull(user)) {
            throw new RuntimeException("用户名或密码错误");
        }
        //TODO 查询对应的权限信息
        return new LoginUser(user);
    }
}
```

(2)配置Security，使定义加密方式

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
```

