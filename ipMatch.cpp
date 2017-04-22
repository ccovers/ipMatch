
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <queue>
#include <map>
#include <string>
#include <algorithm>
#include <fstream>
using namespace std;


#define LINE_MAX 1024

typedef struct _IpInfo
{
	uint32_t minIp;
	uint32_t maxIp;
	string	address;
	string	operators;
}IpInfo;

typedef struct _IP_ADDR
{
	union {
		struct { char s_b1, s_b2, s_b3, s_b4; } S_un_b;
		struct { short s_w1, s_w2; } S_un_w;
		long S_addr;
	};
}IP_ADDR;


map<uint32_t, IpInfo> g_ipRule;//保存ip库信息
map<uint32_t, uint32_t> g_ipRuleRefer;//保存g_ipRule的索引

//排序vector，用于结果排序
typedef pair<string, uint32_t> PAIR;
bool cmp_by_value(const PAIR& lhs, const PAIR& rhs) {
	return lhs.second > rhs.second;
}
struct CmpByValue {
	bool operator()(const PAIR& lhs, const PAIR& rhs) {
		return lhs.second > rhs.second;
	}
};


//解析ip库的一行，取出ip范围及地区和运营商
void getMatchVaue(const char *var, uint32_t index)
{
	int arry[10] = { 0 };
	int count = 0;
	for (int i = 0; i < strlen(var); i++)
	{
		if ('|' == var[i]
			&& count < 10)
		{
			arry[count++] = i;
		}
	}
	if (count < 10)
	{
		return;
	}

	char buf[LINE_MAX] = { 0 };

	//获取最小ip
	memset(buf, 0, LINE_MAX);
	memcpy(buf, var + arry[1] + 1, arry[2] - arry[1] - 1);
	uint32_t minIp = strtoul(buf, NULL, 0);
	
	//获取最大ip
	memset(buf, 0, LINE_MAX);
	memcpy(buf, var + arry[2] + 1, arry[3] - arry[2] - 1);
	uint32_t maxIp = strtoul(buf, NULL, 0);

	//获取地区
	string address;
	memset(buf, 0, LINE_MAX);
	memcpy(buf, var + arry[5] + 1, arry[6] - arry[5] - 1);
	address += buf;
	memset(buf, 0, LINE_MAX);
	memcpy(buf, var + arry[6] + 1, arry[7] - arry[6] - 1);
	address += buf;
    //获取运营商
	string operators;
	memset(buf, 0, LINE_MAX);
	memcpy(buf, var + arry[8] + 1, arry[9] - arry[8] - 1);
	operators += buf;

	IpInfo ipInfo;
	ipInfo.minIp = minIp;
	ipInfo.maxIp = maxIp;
	ipInfo.address = address;
	ipInfo.operators = operators;

	g_ipRule[minIp] = ipInfo;//最小ip作为key，必须保证ip库是顺序增长的，否则匹配算法有误
	g_ipRuleRefer[index] = minIp;//保存g_ipRule的key索引，在匹配算法中使用
}

//遍历ip库，获取ip库信息，保存到内存中
void getIpRule(const char *ipDataFile)
{
	ifstream ipLibary(ipDataFile, ios::in);
	if (!ipLibary.is_open())
	{
		cout << "error open file" << endl;
		return;
	}
	
	uint32_t index = 0;
	std::string line;
	while (std::getline(ipLibary, line))
	{
		getMatchVaue(line.c_str(), index);
		printf("%d\n", index++);
	}
	ipLibary.close();
}


//ip匹配算法，二分查找法
//保证该算法的前提是，g_ipRule中的minIp和maxIp是逐渐增长的
int getMapIndex(uint32_t ip, uint32_t mapOffset, uint32_t mapSize, uint32_t &start, uint32_t &endip)
{
	uint32_t half = mapSize / 2;
	uint32_t midIndex = mapOffset + half;

	uint32_t index = g_ipRuleRefer.at(midIndex);//取得中间元素的索引
	IpInfo &ipInfo = g_ipRule.at(index);//通过索引找到中间元素

	if (ip >= ipInfo.minIp
		&& ip <= ipInfo.maxIp)
	{
		//匹配到
		start = ipInfo.minIp;
		endip = ipInfo.maxIp;
		return midIndex;
	}
	else if (ip < ipInfo.minIp)
	{
		if (half != 0)
		{
			//ip比当前元素的minIp小，查找前半部分
			return getMapIndex(ip, mapOffset, midIndex - mapOffset, start, endip);
		}
	}
	else  if (ip > ipInfo.maxIp)
	{
		if (half != 0)
		{
			//ip比当前元素的maxIp大，查找后半部分
			return getMapIndex(ip, midIndex + 1, mapSize - half - 1, start, endip);
		}
	}

	return -1;
}

//判断每个ip的地区和运营商
void getSection(const char *ips, ofstream &ipDst, map<string, uint32_t> &l_mapOperators)
{
	static char buf[LINE_MAX];
	memset(buf, 0, LINE_MAX);

	uint32_t ip = strtoul(ips, NULL, 0);
	IP_ADDR adr;
	adr.S_addr = ip;//此处获取的ip是网络序的整形
	//dr.S_addr = htonl(ip);//获取的ip是主机序，需转化

	uint32_t startip;
	uint32_t endip;
	int index = getMapIndex(adr.S_addr, 0, g_ipRuleRefer.size(), startip, endip);
	if (index != -1)
	{
		IpInfo &ipInfo = g_ipRule.at(g_ipRuleRefer.at(index));

		/*sprintf_s(buf, "%u|%d.%d.%d.%d|%s|%s----------startip[%u]----endip[%u]\n",
			adr.S_un.S_addr, adr.S_un.S_un_b.s_b1, adr.S_un.S_un_b.s_b2, adr.S_un.S_un_b.s_b3, adr.S_un.S_un_b.s_b4,
			ipInfo.address.c_str(), ipInfo.operators.c_str(), startip, endip);
		ipDst.write(buf, strlen(buf));*/

		if (ipInfo.operators.empty()
			&& ipInfo.address.empty())
		{
			//运营商和地区都没有的ip打印出来
			sprintf(buf, "%u|%d.%d.%d.%d\n",
				adr.S_addr, adr.S_un_b.s_b4, adr.S_un_b.s_b3, adr.S_un_b.s_b2, adr.S_un_b.s_b1);
			ipDst.write(buf, strlen(buf));

			string unknown = "unknown";
			map<string, uint32_t>::iterator operatorsIt = l_mapOperators.find(unknown);
			if (operatorsIt != l_mapOperators.end())
			{
				operatorsIt->second++;
			}
			else
			{
				l_mapOperators[unknown] = 1;
			}
		}
		else
		{
			string keyString;
			if (!ipInfo.operators.empty())
			{
				if ("qqzeng-ip" == ipInfo.operators)
				{
					keyString = "IANA保留地址";//一般是局域网地址
				}
				else
				{
					keyString = ipInfo.operators;
				}
			}
			else
			{
				keyString = ipInfo.address;//没有运营商就是用地区代替
			}
			
			map<string, uint32_t>::iterator operatorsIt = l_mapOperators.find(keyString);
			if (operatorsIt != l_mapOperators.end())
			{
				operatorsIt->second++;
			}
			else
			{
				l_mapOperators[keyString] = 1;
			}
		}
	}
	else
	{
		string unknown = "国外";//该ip库是国内的，因此国外的ip都找不到
		map<string, uint32_t>::iterator operatorsIt = l_mapOperators.find(unknown);
		if (operatorsIt != l_mapOperators.end())
		{
			operatorsIt->second++;
		}
		else
		{
			l_mapOperators[unknown] = 1;
		}
	}
}

//遍历ip地址文件，将结果保存到另一个文件中
void defferentiateIp(const char *ipsrc)
{
    printf("file start ... %s\n", ipsrc);
	ifstream ipSrc(ipsrc, ios::in);
	ofstream ipDst((string(ipsrc) + ".bak_s").c_str(), ios::out);
	map<string, uint32_t> l_mapOperators;

	char buf[LINE_MAX] = { 0 };
	if (!ipDst.is_open()
		|| !ipSrc.is_open())
	{
		cout << "error open file" << endl;
		return;
	}

	time_t tm = time(NULL);
	uint32_t count = 0;
	std::string line;
	while (std::getline(ipSrc, line))
	{
		getSection(line.c_str(), ipDst, l_mapOperators);

		count++;
		if (count % 10000 == 0)
		{
			//没遍历一万个ip，打印数量及速度
			time_t tm_t = time(NULL);
			time_t ts = (tm_t - tm);
            if(ts != 0)
            {
			    printf("process : count[%u]	time[%d]second	speed[%u]\n", count, ts, count / ts);
		    }
        }
	}

    printf("file end ...\n");
	
	//将结果保存到文件中
	map<string, uint32_t>::iterator operatorsIt = l_mapOperators.begin();
	uint32_t totalCoutn = 0;
	while (operatorsIt != l_mapOperators.end())
	{
		totalCoutn += operatorsIt->second;
		operatorsIt++;
	}
	char lines[LINE_MAX] = { 0 };
	sprintf(lines, "运营商\t\t\t数量\t\t百分比\n");
	ipDst.write(lines, strlen(lines));

	std::vector<PAIR> name_score_vec(l_mapOperators.begin(), l_mapOperators.end());
	std::sort(name_score_vec.begin(), name_score_vec.end(), CmpByValue());

	vector<PAIR>::iterator vecIt = name_score_vec.begin();
	while (vecIt != name_score_vec.end())
	{
		char line[LINE_MAX] = { 0 };
		sprintf(line, "%s\t\t\t%d\t\t%f\n", vecIt->first.c_str(), vecIt->second, ((float)vecIt->second / (float)totalCoutn) * 100);
		ipDst.write(line, strlen(line));
		vecIt++;
	}

	ipDst.close();
	ipSrc.close();
}


int main(int argc, char* argv[])
{
	//解析ip库文件
	getIpRule("ip_database_161243.txt");
    if(g_ipRule.empty())
    {//ip库解析为空则退出
        return 0;
    }
	
	//遍历ip文件（批文件中保存ip的整形如：1001127967）
	defferentiateIp("ip.txt");

	return 0;
}

