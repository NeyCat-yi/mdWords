# Spring Security使用

### 1、快速入门

###### 1.1导入security

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

###### 1.2准备工作

创建springBoot工程



### 2、认证

#### 2.1准备工作

- 导入依赖

  ```xml
   		<!--redis依赖-->
          <dependency>
              <groupId>org.springframework.boot</groupId>
              <artifactId>spring-boot-starter-data-redis</artifactId>
          </dependency>
          <!--fastjson依赖-->
          <dependency>
              <groupId>com.alibaba</groupId>
              <artifactId>fastjson</artifactId>
              <version>1.2.33</version>
          </dependency>
          <!--jwt依赖-->
          <dependency>
              <groupId>io.jsonwebtoken</groupId>
              <artifactId>jjwt</artifactId>
              <version>0.9.0</version>
          </dependency>
  ```

- 配置Redis相关配置

  - utils工具类

    ```java
    import com.alibaba.fastjson.JSON;
    import com.alibaba.fastjson.parser.ParserConfig;
    import com.alibaba.fastjson.serializer.SerializerFeature;
    import com.fasterxml.jackson.databind.JavaType;
    import com.fasterxml.jackson.databind.type.TypeFactory;
    import org.springframework.data.redis.serializer.RedisSerializer;
    import org.springframework.data.redis.serializer.SerializationException;
    
    import java.nio.charset.Charset;
    /**
     * Redis使用FastJson序列化
     * 
     * @author sg
     */
    public class FastJsonRedisSerializer<T> implements RedisSerializer<T>
    {
    
        public static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");
    
        private Class<T> clazz;
    
        static
        {
            ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        }
    
        public FastJsonRedisSerializer(Class<T> clazz)
        {
            super();
            this.clazz = clazz;
        }
    
        @Override
        public byte[] serialize(T t) throws SerializationException
        {
            if (t == null)
            {
                return new byte[0];
            }
            return JSON.toJSONString(t, SerializerFeature.WriteClassName).getBytes(DEFAULT_CHARSET);
        }
    
        @Override
        public T deserialize(byte[] bytes) throws SerializationException
        {
            if (bytes == null || bytes.length <= 0)
            {
                return null;
            }
            String str = new String(bytes, DEFAULT_CHARSET);
    
            return JSON.parseObject(str, clazz);
        }
    
    
        protected JavaType getJavaType(Class<?> clazz)
        {
            return TypeFactory.defaultInstance().constructType(clazz);
        }
    }
    ```

    

  - 配置类

    ```java
    import com.yi.utils.FastJsonRedisSerializer;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.data.redis.connection.RedisConnectionFactory;
    import org.springframework.data.redis.core.RedisTemplate;
    import org.springframework.data.redis.serializer.StringRedisSerializer;
    
    @Configuration
    public class RedisConfig {
    
        @Bean
        @SuppressWarnings(value = { "unchecked", "rawtypes" })
        public RedisTemplate<Object, Object> redisTemplate(RedisConnectionFactory connectionFactory)
        {
            RedisTemplate<Object, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(connectionFactory);
    
            FastJsonRedisSerializer serializer = new FastJsonRedisSerializer(Object.class);
    
            // 使用StringRedisSerializer来序列化和反序列化redis的key值
            template.setKeySerializer(new StringRedisSerializer());
            template.setValueSerializer(serializer);
    
            // Hash的key也采用StringRedisSerializer的序列化方式
            template.setHashKeySerializer(new StringRedisSerializer());
            template.setHashValueSerializer(serializer);
    
            template.afterPropertiesSet();
            return template;
        }
    }
    ```

    

- 响应类

  ```java
  import com.fasterxml.jackson.annotation.JsonInclude;
  import lombok.Data;
  /**
   * @Author 三更  B站： https://space.bilibili.com/663528522
   */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  @Data
  public class ResponseResult<T> {
      /**
       * 状态码
       */
      private Integer code;
      /**
       * 提示信息，如果有错误时，前端可以获取该字段进行提示
       */
      private String msg;
      /**
       * 查询到的结果数据，
       */
      private T data;
  
      public ResponseResult(Integer code, String msg) {
          this.code = code;
          this.msg = msg;
      }
  
      public ResponseResult(Integer code, T data) {
          this.code = code;
          this.data = data;
      }
  
      public ResponseResult(Integer code, String msg, T data) {
          this.code = code;
          this.msg = msg;
          this.data = data;
      }
  }
  ```

  

- 工具类

  ```java
  import io.jsonwebtoken.Claims;
  import io.jsonwebtoken.JwtBuilder;
  import io.jsonwebtoken.Jwts;
  import io.jsonwebtoken.SignatureAlgorithm;
  
  import javax.crypto.SecretKey;
  import javax.crypto.spec.SecretKeySpec;
  import java.util.Base64;
  import java.util.Date;
  import java.util.UUID;
  
  /**
   * JWT工具类
   */
  public class JwtUtil {
  
      //有效期为
      public static final Long JWT_TTL = 60 * 60 *1000L;// 60 * 60 *1000  一个小时
      //设置秘钥明文
      public static final String JWT_KEY = "wenyi0";
  
      public static String getUUID(){
          String token = UUID.randomUUID().toString().replaceAll("-", "");
          return token;
      }
      
      /**
       * 生成jtw
       * @param subject token中要存放的数据（json格式）
       * @return
       */
      public static String createJWT(String subject) {
          JwtBuilder builder = getJwtBuilder(subject, null, getUUID());// 设置过期时间
          return builder.compact();
      }
  
      /**
       * 生成jtw
       * @param subject token中要存放的数据（json格式）
       * @param ttlMillis token超时时间
       * @return
       */
      public static String createJWT(String subject, Long ttlMillis) {
          JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID());// 设置过期时间
          return builder.compact();
      }
  
      private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid) {
          SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
          SecretKey secretKey = generalKey();
          long nowMillis = System.currentTimeMillis();
          Date now = new Date(nowMillis);
          if(ttlMillis==null){
              ttlMillis=JwtUtil.JWT_TTL;
          }
          long expMillis = nowMillis + ttlMillis;
          Date expDate = new Date(expMillis);
          return Jwts.builder()
                  .setId(uuid)              //唯一的ID
                  .setSubject(subject)   // 主题  可以是JSON数据
                  .setIssuer("wenyi")     // 签发者
                  .setIssuedAt(now)      // 签发时间
                  .signWith(signatureAlgorithm, secretKey) //使用HS256对称加密算法签名, 第二个参数为秘钥
                  .setExpiration(expDate);
      }
  
      /**
       * 创建token
       * @param id
       * @param subject
       * @param ttlMillis
       * @return
       */
      public static String createJWT(String id, String subject, Long ttlMillis) {
          JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id);// 设置过期时间
          return builder.compact();
      }
  
      public static void main(String[] args) throws Exception {
  //        String jwt = createJWT("2123");
          Claims claims = parseJWT("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyOTY2ZGE3NGYyZGM0ZDAxOGU1OWYwNjBkYmZkMjZhMSIsInN1YiI6IjIiLCJpc3MiOiJzZyIsImlhdCI6MTYzOTk2MjU1MCwiZXhwIjoxNjM5OTY2MTUwfQ.NluqZnyJ0gHz-2wBIari2r3XpPp06UMn4JS2sWHILs0");
          String subject = claims.getSubject();
          System.out.println(subject);
  //        System.out.println(claims);
      }
  
      /**
       * 生成加密后的秘钥 secretKey
       * @return
       */
      public static SecretKey generalKey() {
          byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
          SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
          return key;
      }
      
      /**
       * 解析
       *
       * @param jwt
       * @return
       * @throws Exception
       */
      public static Claims parseJWT(String jwt) throws Exception {
          SecretKey secretKey = generalKey();
          return Jwts.parser()
                  .setSigningKey(secretKey)
                  .parseClaimsJws(jwt)
                  .getBody();
      }
  
  
  }
  ```

  ```java
  import org.springframework.beans.factory.annotation.Autowired;
  import org.springframework.data.redis.core.BoundSetOperations;
  import org.springframework.data.redis.core.HashOperations;
  import org.springframework.data.redis.core.RedisTemplate;
  import org.springframework.data.redis.core.ValueOperations;
  import org.springframework.stereotype.Component;
  
  import java.util.*;
  @SuppressWarnings(value = { "unchecked", "rawtypes" })
  @Component
  public class RedisCache{
      
      @Autowired
      public RedisTemplate redisTemplate;
  
      /**
       * 缓存基本的对象，Integer、String、实体类等
       *
       * @param key 缓存的键值
       * @param value 缓存的值
       */
      public <T> void setCacheObject(final String key, final T value)
      {
          redisTemplate.opsForValue().set(key, value);
      }
  
      /**
       * 缓存基本的对象，Integer、String、实体类等
       *
       * @param key 缓存的键值
       * @param value 缓存的值
       * @param timeout 时间
       * @param timeUnit 时间颗粒度
       */
      public <T> void setCacheObject(final String key, final T value, final Integer timeout, final TimeUnit timeUnit)
      {
          redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
      }
  
      /**
       * 设置有效时间
       *
       * @param key Redis键
       * @param timeout 超时时间
       * @return true=设置成功；false=设置失败
       */
      public boolean expire(final String key, final long timeout)
      {
          return expire(key, timeout, TimeUnit.SECONDS);
      }
  
      /**
       * 设置有效时间
       *
       * @param key Redis键
       * @param timeout 超时时间
       * @param unit 时间单位
       * @return true=设置成功；false=设置失败
       */
      public boolean expire(final String key, final long timeout, final TimeUnit unit)
      {
          return redisTemplate.expire(key, timeout, unit);
      }
  
      /**
       * 获得缓存的基本对象。
       *
       * @param key 缓存键值
       * @return 缓存键值对应的数据
       */
      public <T> T getCacheObject(final String key)
      {
          ValueOperations<String, T> operation = redisTemplate.opsForValue();
          return operation.get(key);
      }
  
      /**
       * 删除单个对象
       *
       * @param key
       */
      public boolean deleteObject(final String key)
      {
          return redisTemplate.delete(key);
      }
  
      /**
       * 删除集合对象
       *
       * @param collection 多个对象
       * @return
       */
      public long deleteObject(final Collection collection)
      {
          return redisTemplate.delete(collection);
      }
  
      /**
       * 缓存List数据
       *
       * @param key 缓存的键值
       * @param dataList 待缓存的List数据
       * @return 缓存的对象
       */
      public <T> long setCacheList(final String key, final List<T> dataList)
      {
          Long count = redisTemplate.opsForList().rightPushAll(key, dataList);
          return count == null ? 0 : count;
      }
  
      /**
       * 获得缓存的list对象
       *
       * @param key 缓存的键值
       * @return 缓存键值对应的数据
       */
      public <T> List<T> getCacheList(final String key)
      {
          return redisTemplate.opsForList().range(key, 0, -1);
      }
  
      /**
       * 缓存Set
       *
       * @param key 缓存键值
       * @param dataSet 缓存的数据
       * @return 缓存数据的对象
       */
      public <T> BoundSetOperations<String, T> setCacheSet(final String key, final Set<T> dataSet)
      {
          BoundSetOperations<String, T> setOperation = redisTemplate.boundSetOps(key);
          Iterator<T> it = dataSet.iterator();
          while (it.hasNext())
          {
              setOperation.add(it.next());
          }
          return setOperation;
      }
  
      /**
       * 获得缓存的set
       *
       * @param key
       * @return
       */
      public <T> Set<T> getCacheSet(final String key)
      {
          return redisTemplate.opsForSet().members(key);
      }
  
      /**
       * 缓存Map
       *
       * @param key
       * @param dataMap
       */
      public <T> void setCacheMap(final String key, final Map<String, T> dataMap)
      {
          if (dataMap != null) {
              redisTemplate.opsForHash().putAll(key, dataMap);
          }
      }
  
      /**
       * 获得缓存的Map
       *
       * @param key
       * @return
       */
      public <T> Map<String, T> getCacheMap(final String key)
      {
          return redisTemplate.opsForHash().entries(key);
      }
  
      /**
       * 往Hash中存入数据
       *
       * @param key Redis键
       * @param hKey Hash键
       * @param value 值
       */
      public <T> void setCacheMapValue(final String key, final String hKey, final T value)
      {
          redisTemplate.opsForHash().put(key, hKey, value);
      }
  
      /**
       * 获取Hash中的数据
       *
       * @param key Redis键
       * @param hKey Hash键
       * @return Hash中的对象
       */
      public <T> T getCacheMapValue(final String key, final String hKey)
      {
          HashOperations<String, String, T> opsForHash = redisTemplate.opsForHash();
          return opsForHash.get(key, hKey);
      }
  
      /**
       * 删除Hash中的数据
       * 
       * @param key
       * @param hkey
       */
      public void delCacheMapValue(final String key, final String hkey)
      {
          HashOperations hashOperations = redisTemplate.opsForHash();
          hashOperations.delete(key, hkey);
      }
  
      /**
       * 获取多个Hash中的数据
       *
       * @param key Redis键
       * @param hKeys Hash键集合
       * @return Hash对象集合
       */
      public <T> List<T> getMultiCacheMapValue(final String key, final Collection<Object> hKeys)
      {
          return redisTemplate.opsForHash().multiGet(key, hKeys);
      }
  
      /**
       * 获得缓存的基本对象列表
       *
       * @param pattern 字符串前缀
       * @return 对象列表
       */
      public Collection<String> keys(final String pattern)
      {
          return redisTemplate.keys(pattern);
      }
  }
  ```

  ```java
  import javax.servlet.http.HttpServletResponse;
  import java.io.IOException;
  public class WebUtils
  {
      /**
       * 将字符串渲染到客户端
       * 
       * @param response 渲染对象
       * @param string 待渲染的字符串
       * @return null
       */
      public static String renderString(HttpServletResponse response, String string) {
          try
          {
              response.setStatus(200);
              response.setContentType("application/json");
              response.setCharacterEncoding("utf-8");
              response.getWriter().print(string);
          }
          catch (IOException e)
          {
              e.printStackTrace();
          }
          return null;
      }
  }
  ```

  



#### 2.2思路分析

**登录**

​	（1）自定义登录接口

​			调用ProviderManager的方法进行认证 如果认证通过生成jwt

​			把用户信息存入redis中

​	（2）自定义UserDetailsService

​			在这个实现类中去查询数据库

**校验**

​	（1）定义jwt认证过滤器

​			获取token

​			解析token获取其中的userId

​			从redis中获取用户信息

​			存入SecurityContextHolder



#### 2.3实现

##### 2.3.1数据库校验用户

实现UserDetailsService接口，输入用户名密码时与数据库做校验

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

(2)定义实体类LoginUser实现UserDetails

```java
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginUser implements UserDetails {

    @Autowired
    private User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

```

##### 2.3.2密码加密存储

添加配置类SecurityConfig，使定义加密方式

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
```

##### 2.3.3登录接口

我们需要自定义登录接口，然后让SpingSecurity对这个接口放行，让用户访问这个接口的时候不用登陆也能访问

在接口中我们通过AuthenticationManager中的authenticate方法来进行用户认证，所有需要在SecurityConfig中配置把AuthenticationManager注入容器

认证成功的话要生成一个jwt，放入响应中返回并且为了让用户下次请求时能通过jwt识别出具体的时哪个用户，我们需要把用户信息存入Redis，可以把用户id作为key

（1）接口放行，在SecurityConfig中重写方法

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口 允许匿名访问
                .antMatchers("/login").anonymous()
                .antMatchers("/users").anonymous()
//                .antMatchers("/testCors").hasAuthority("system:dept:list222")
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();
    }
```

（1）SecurityConfig把AuthenticationManager注入容器

```java
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
```

（2）具体代码

```java
@Service
public class LoginServiceImpl implements LoginServcie {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
        //AuthenticationManager authenticate进行用户认证
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(),user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        //如果认证没通过，给出对应的提示
        if(Objects.isNull(authenticate)){
            throw new RuntimeException("登录失败");
        }
        //如果认证通过了，使用userid生成一个jwt jwt存入ResponseResult返回
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userid = loginUser.getUser().getId().toString();
        String jwt = JwtUtil.createJWT(userid);
        Map<String,String> map = new HashMap<>();
        map.put("token",jwt);
        //把完整的用户信息存入redis  userid作为key
        redisCache.setCacheObject("login:"+userid,loginUser);
        return new ResponseResult(200,"登录成功",map);
    }

    @Override
    public ResponseResult logout() {
        //获取SecurityContextHolder中的用户id
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        Long userid = loginUser.getUser().getId();
        //删除redis中的值
        redisCache.deleteObject("login:"+userid);
        return new ResponseResult(200,"注销成功");
    }
}
```

##### 2.34认证过滤器

​			获取token

​			解析token获取其中的userId

​			从redis中获取用户信息

​			存入SecurityContextHolder

（1）在filter文件夹下添加过滤器

```java
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
            //放行
            filterChain.doFilter(request, response);
            return;
        }
        //解析token
        String userid;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userid = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }
        //从redis中获取用户信息
        String redisKey = "login:" + userid;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if(Objects.isNull(loginUser)){
            throw new RuntimeException("用户未登录");
        }
        //存入SecurityContextHolder
        //TODO 获取权限信息封装到Authentication中
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginUser,null,loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        //放行
        filterChain.doFilter(request, response);
    }
}
```

在SecurityConfig配置类中 configure(HttpSecurity http)方法下添加过滤器

```java
   // 注入jwt过滤器
	@Autowired
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
		//添加过滤器
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
```

