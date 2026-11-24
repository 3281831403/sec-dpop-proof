资源服务器加了持有者证明之后，把同一份证明换个请求地址重放，居然还能通过：1 方法比较区分大小写导致大小写变体被拒；2 地址归一不去默认端口导致等价地址被判不同；3 地址归一不排序查询参数导致参数顺序变化被判不同；4 令牌摘要缺失时跳过校验导致未绑定令牌的证明被接受；5 令牌摘要用前缀比较导致短摘要即可通过；6 一次性标识只记录不查询导致同一证明可重放；7 一次性存储不清理过期项导致长期运行后内存无界；8 时间窗只校验是否过旧导致未来时间戳被接受；9 时间窗用绝对差而不区分方向导致窗口被放大一倍；10 批量校验复用证明载荷导致第二个请求沿用第一个请求的载荷。engine/dpop/proof.py 是核心，tests/dpop/test_proof.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

字段表
安全        漏洞检测与攻防
类型        Bugfix
环境        Python 3, pytest
依赖        无外部依赖

运行方式
在仓库根目录执行
python -m pytest tests -q
初始预期输出尾部为 15 failed，且 15 个失败全部来自 NotImplementedError。修复完成后应变为 15 passed。

测试约束
tests/dpop/test_proof.py 不可修改，也不可删除或跳过测试。测试只依赖标准库和 pytest。
engine 采用嵌套布局，导入路径为 engine.dpop.proof。不要压平目录，不要移动实现文件。
唯一实现文件是 engine/dpop/proof.py。其余文件是判题基础设施，不应改变行为。

目录结构
sec-dpop-proof
  README.md
  conftest.py
  engine
    __init__.py
    dpop
      __init__.py
      proof.py
  tests
    dpop
      test_proof.py

实现约束
proof.py 恰好保留 8 个公开桩，初始状态全部只有 raise NotImplementedError。
8 个桩依次是 split_proof、normalize_url、check_htm、check_htu、check_ath、check_jti、check_time、proof_batch。
证明是点分隔的三段紧凑序列化结构，第一段为头部，第二段为载荷，第三段为签名。签名真实性由上游验证，本模块负责绑定语义与重放防护。
批量校验必须逐个请求读取自己的证明，任何请求失败都不得污染后续请求。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

