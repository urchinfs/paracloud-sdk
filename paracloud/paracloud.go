/*
 *     Copyright 2022 The Urchin Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package paracloud

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/studio-b12/gowebdav"
	"github.com/urchinfs/paracloud-sdk/types"
	"github.com/urchinfs/paracloud-sdk/util"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Client interface {
	BucketExists(ctx context.Context, bucketName string) (bool, error)

	ListBuckets(ctx context.Context) ([]BucketInfo, error)

	StatFile(ctx context.Context, bucketName, fileName string) (FileInfo, error)

	UploadFile(ctx context.Context, bucketName, fileName, digest string, reader io.Reader) error

	DownloadFile(ctx context.Context, bucketName, fileName string) (io.ReadCloser, error)

	RemoveFile(ctx context.Context, bucketName, fileName string) error

	RemoveFiles(ctx context.Context, bucketName string, objects []*FileInfo) error

	ListFiles(ctx context.Context, bucketName, prefix, marker string, limit int64) ([]*FileInfo, error)

	ListDirFiles(ctx context.Context, bucketName, prefix string) ([]*FileInfo, error)

	IsFileExist(ctx context.Context, bucketName, fileName string) (bool, error)

	IsBucketExist(ctx context.Context, bucketName string) (bool, error)

	GetDownloadLink(ctx context.Context, bucketName, fileName string, expire time.Duration) (string, error)

	CreateDir(ctx context.Context, bucketName, folderName string) error

	GetDirMetadata(ctx context.Context, bucketName, folderKey string) (*FileInfo, bool, error)

	PostTransfer(ctx context.Context, bucketName, fileName string, isSuccess bool) error
}

type client struct {
	httpClient           *resty.Client
	redisStorage         *util.RedisStorage
	token                string
	tokenExpireTimestamp int64
	username             string
	password             string
	paraCloudUrl         string
	urchinCacheHashKey   string
	redisEndpoints       []string
	redisPassword        string
	enableCluster        bool
}

func New(username, password, paraCloudUrl, urchinCacheHashKey string, redisEndpoints []string, redisPassword string, enableCluster bool) (Client, error) {
	b := &client{
		username:           username,
		password:           password,
		paraCloudUrl:       paraCloudUrl,
		urchinCacheHashKey: urchinCacheHashKey,
		redisEndpoints:     redisEndpoints,
		redisPassword:      redisPassword,
		enableCluster:      enableCluster,
		httpClient:         resty.New(),
		redisStorage:       util.NewRedisStorage(redisEndpoints, redisPassword, enableCluster),
	}
	b.httpClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	if b.username == "" || b.password == "" || b.paraCloudUrl == "" || b.urchinCacheHashKey == "" {
		return nil, types.ErrorInvalidParameter
	}

	if b.redisStorage == nil {
		return nil, errors.New("init redis error")
	}

	return b, nil
}

type BucketInfo struct {
	// The name of the Bucket.
	Name string `json:"name"`
	// Date the Bucket was created.
	CreationDate time.Time `json:"creationDate"`
}

type FileInfo struct {
	Key          string
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
	Expires      time.Time
	Metadata     http.Header
}

type Reply struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type GetClusterAccountResp struct {
	List []struct {
		ClusterID string `json:"clusterID"`
		AccountID string `json:"accountID"`
	} `json:"accounts"`
}

type Service struct {
}

type CreateVolumeReq struct {
	Service Service `json:"service"`
}

type CreateVolumeReply struct {
	Id        string `json:"id"`
	ClusterID string `json:"clusterID"`
	AccountID string `json:"accountID"`
	Service   struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Address  struct {
			Webdav string `json:"webdav"`
			Sftp   string `json:"sftp"`
		} `json:"address"`
	} `json:"service"`
}

type webDavInfo struct {
	id        string
	clusterID string
	accountID string
	username  string
	password  string
	url       string
}

func needRetry(r *Reply) bool {
	if r.Code == 4000 {
		return true
	}

	return false
}

func parseBody(ctx context.Context, reply []byte, body interface{}) error {
	if body != nil {
		err := json.Unmarshal(reply, body)
		if err != nil {
			return errors.New("reply.Data parse error")
		}
	}

	return nil
}

func (c *client) sendHttpRequest(ctx context.Context, httpMethod, httpPath string, jsonBody string, respData interface{}) error {
	httpUrl := c.paraCloudUrl + strings.TrimLeft(httpPath, "/")
	for {
		r := &Reply{}
		response := &resty.Response{}
		var err error
		if httpMethod == types.HttpMethodGet {
			response, err = c.httpClient.R().
				SetHeader(types.AuthHeader, c.token).
				SetResult(r).
				Get(httpUrl)
			if err != nil {
				return err
			}
		} else if httpMethod == types.HttpMethodPost {
			response, err = c.httpClient.R().
				SetHeader("Content-Type", "application/json").
				SetHeader(types.AuthHeader, c.token).
				SetBody(jsonBody).SetResult(r).
				Post(httpUrl)
			if err != nil {
				return err
			}
		} else if httpMethod == types.HttpMethodDelete {
			response, err = c.httpClient.R().
				SetHeader(types.AuthHeader, c.token).
				SetResult(r).
				Delete(httpUrl)
			if err != nil {
				return err
			}
		} else {
			return types.ErrorInternal
		}

		if !response.IsSuccess() {
			err := json.Unmarshal(response.Body(), r)
			if err == nil {
				if needRetry(r) {
					time.Sleep(time.Second * 21)
					continue
				}
			}

			return errors.New("Code:" + strconv.FormatInt(int64(response.StatusCode()), 10) + ", Msg:" + string(response.Body()))
		}

		if r.Code != 0 {
			return errors.New("Code:" + strconv.FormatInt(r.Code, 10) + ", Msg:" + r.Message)
		}

		err = parseBody(ctx, response.Body(), respData)
		if err != nil {
			return err
		}

		break
	}

	return nil
}

func (c *client) getToken(ctx context.Context, username, password string) (string, error) {
	urlPath := fmt.Sprintf("/user/api/login?token_type=TOKEN&third_party=SELF&email=%s&password=%s", username, password)
	r := &Reply{}
	response, err := c.httpClient.R().
		SetHeader("Content-Type", "application/json").
		SetBody(nil).SetResult(r).Post(types.ParaTokenUrl + urlPath)
	if err != nil {
		return "", err
	}

	if !response.IsSuccess() {
		return "", err
	}

	if response.Header().Get(types.AuthRespHeader) == "" {
		return "", errors.New("authentication Failed")
	}
	authToken := "Bearer " + response.Header().Get(types.AuthRespHeader)

	return authToken, nil
}

func (c *client) refreshToken(ctx context.Context) error {
	tokenKey := c.redisStorage.MakeStorageKey([]string{}, types.StoragePrefixParaCloudToken)
	value, err := c.redisStorage.Get(tokenKey)
	if err != nil {
		if err == types.ErrorNotExists {
			token, err := c.getToken(ctx, c.username, c.password)
			if err != nil {
				return err
			}

			c.token = token
			err = c.redisStorage.SetWithTimeout(tokenKey, []byte(token), types.DefaultTokenExpireTime)
			if err != nil {
				return err
			}
		}

		return err
	}

	c.token = string(value)
	return nil
}

func (c *client) refreshVolumeCache(ctx context.Context) (webDavInfo, error) {
	volumeKey := c.redisStorage.MakeStorageKey([]string{c.urchinCacheHashKey}, types.StoragePrefixParaCloudVolume)
	exists, err := c.redisStorage.Exists(volumeKey)
	if err != nil {
		return webDavInfo{}, err
	}

	if exists {
		values, err := c.redisStorage.ReadMap(volumeKey)
		if err != nil {
			return webDavInfo{}, err
		}

		return webDavInfo{
			id:        string(values["id"]),
			clusterID: string(values["clusterID"]),
			accountID: string(values["accountID"]),
			username:  string(values["username"]),
			password:  string(values["password"]),
			url:       string(values["url"]),
		}, nil
	}

	volume, err := c.createClusterVolume(ctx)
	if err != nil {
		return webDavInfo{}, err
	}

	values := make(map[string]interface{})
	values["id"] = volume.id
	values["clusterID"] = volume.clusterID
	values["accountID"] = volume.accountID
	values["username"] = volume.username
	values["password"] = volume.password
	values["url"] = volume.url
	err = c.redisStorage.SetMapElements(volumeKey, values)
	if err != nil {
		return webDavInfo{}, err
	}

	return volume, nil
}

func (c *client) createClusterVolume(ctx context.Context) (webDavInfo, error) {
	err := c.refreshToken(ctx)
	if err != nil {
		return webDavInfo{}, err
	}

	resp := &GetClusterAccountResp{}
	urlPath := fmt.Sprintf("/api/v1rc1/clusters/-/accounts")
	err = c.sendHttpRequest(ctx, types.HttpMethodGet, urlPath, "", resp)
	if err != nil {
		return webDavInfo{}, err
	}

	if len(resp.List) <= 0 {
		return webDavInfo{}, errors.New("no available cluster")
	}

	clusterID := ""
	accountID := ""
	for _, item := range resp.List {
		if item.ClusterID == "NC-N30" {
			clusterID = item.ClusterID
			accountID = item.AccountID
			break
		}
	}
	if clusterID == "" {
		return webDavInfo{}, errors.New("can not get cluster id")
	}

	reqVol := CreateVolumeReq{}
	jsonBody, err := json.Marshal(&reqVol)
	if err != nil {
		return webDavInfo{}, err
	}

	respVol := &CreateVolumeReply{}
	volumeID := c.urchinCacheHashKey
	urlPath = fmt.Sprintf("/api/v1rc1/clusters/%s/accounts/%s/volumes?volumeID=%s", clusterID, accountID, volumeID)
	err = c.sendHttpRequest(ctx, types.HttpMethodPost, urlPath, string(jsonBody), respVol)
	if err != nil {
		return webDavInfo{}, err
	}

	if volumeID != respVol.Id {
		return webDavInfo{}, errors.New("volume id is not match")
	}

	volumeKey := c.redisStorage.MakeStorageKey([]string{c.urchinCacheHashKey}, types.StoragePrefixParaCloudVolume)
	values := make(map[string]interface{})
	values["id"] = respVol.Id
	values["clusterID"] = respVol.ClusterID
	values["accountID"] = respVol.AccountID
	values["username"] = respVol.Service.Username
	values["password"] = respVol.Service.Password
	values["url"] = respVol.Service.Address.Webdav
	err = c.redisStorage.SetMapElements(volumeKey, values)
	if err != nil {
		return webDavInfo{}, err
	}

	return webDavInfo{
		id:        respVol.Id,
		clusterID: respVol.ClusterID,
		accountID: respVol.AccountID,
		username:  respVol.Service.Username,
		password:  respVol.Service.Password,
		url:       respVol.Service.Address.Webdav,
	}, nil
}

func (c *client) removeClusterVolume(ctx context.Context, clusterID, accountID, volumeID string) error {
	err := c.refreshToken(ctx)
	if err != nil {
		return err
	}

	urlPath := fmt.Sprintf("/api/v1rc1/clusters/%s/accounts/%s/volumes/%s?force=true", clusterID, accountID, volumeID)
	err = c.sendHttpRequest(ctx, types.HttpMethodDelete, urlPath, "", nil)
	if err != nil {
		return err
	}

	volumeKey := c.redisStorage.MakeStorageKey([]string{c.urchinCacheHashKey}, types.StoragePrefixParaCloudVolume)
	_ = c.redisStorage.Del(volumeKey)

	return nil
}

func (c *client) BucketExists(ctx context.Context, bucketName string) (bool, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return false, err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	stat, err := webdavClient.Stat(bucketName)
	if err != nil {
		return false, err
	}

	return stat.IsDir(), nil
}

func (c *client) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return []BucketInfo{}, err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	dirs, err := webdavClient.ReadDir("/")
	if err != nil {
		return []BucketInfo{}, err
	}

	var Buckets []BucketInfo
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}

		Buckets = append(Buckets, BucketInfo{
			Name:         dir.Name(),
			CreationDate: dir.ModTime(),
		})
	}

	return Buckets, nil
}

func (c *client) StatFile(ctx context.Context, bucketName, fileName string) (FileInfo, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return FileInfo{}, err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	stat, err := webdavClient.Stat(filepath.Join("/", bucketName, fileName))
	if err != nil {
		return FileInfo{}, err
	}

	if stat.IsDir() {
		return FileInfo{}, errors.New("noSuchKey")
	}

	return FileInfo{
		Key:          fileName,
		Size:         stat.Size(),
		LastModified: stat.ModTime(),
	}, nil
}

func (c *client) UploadFile(ctx context.Context, bucketName, fileName, digest string, reader io.Reader) error {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	err = webdavClient.WriteStream(filepath.Join("/", bucketName, fileName), reader, types.DefaultFileMode)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) DownloadFile(ctx context.Context, bucketName, fileName string) (io.ReadCloser, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return nil, err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	stream, err := webdavClient.ReadStream(filepath.Join("/", bucketName, fileName))
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (c *client) RemoveFile(ctx context.Context, bucketName, fileName string) error {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	err = webdavClient.Remove(filepath.Join("/", bucketName, fileName))
	if err != nil {
		return err
	}

	return nil
}

func (c *client) RemoveFiles(ctx context.Context, bucketName string, objects []*FileInfo) error {
	for _, obj := range objects {
		err := c.RemoveFile(ctx, bucketName, obj.Key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *client) ListFiles(ctx context.Context, bucketName, prefix, marker string, limit int64) ([]*FileInfo, error) {
	if prefix == "." || prefix == ".." {
		return nil, nil
	}

	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return nil, err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	var objects []*FileInfo
	files, err := webdavClient.ReadDir(filepath.Join(bucketName, prefix))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		objects = append(objects, &FileInfo{
			Key:          prefix,
			Size:         file.Size(),
			LastModified: file.ModTime(),
		})
	}

	return objects, nil
}

func (c *client) listDirObjs(ctx context.Context, bucketName, path string, wc *gowebdav.Client) ([]*FileInfo, error) {
	if path == "." || path == ".." {
		return nil, nil
	}

	var objects []*FileInfo
	files, err := wc.ReadDir(filepath.Join(bucketName, path))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {
			objects = append(objects, &FileInfo{
				Key:          filepath.Join(path, file.Name()),
				Size:         file.Size(),
				LastModified: file.ModTime(),
			})
		} else {
			tmpObjs, err := c.listDirObjs(ctx, bucketName, filepath.Join(path, file.Name()), wc)
			if err != nil {
				return nil, err
			}

			objects = append(objects, tmpObjs...)
		}
	}

	return objects, nil
}

func (c *client) ListDirFiles(ctx context.Context, bucketName, prefix string) ([]*FileInfo, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return nil, err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	resp, err := c.listDirObjs(ctx, bucketName, prefix, webdavClient)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	resp = append(resp, &FileInfo{
		Key: prefix,
	})

	return resp, nil
}

func (c *client) IsFileExist(ctx context.Context, bucketName, fileName string) (bool, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return false, err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	stat, err := webdavClient.Stat(filepath.Join("/", bucketName, fileName))
	if err != nil {
		return false, err
	}

	if !stat.IsDir() && stat.Name() == filepath.Base(fileName) {
		return true, nil
	}

	return false, nil
}

func (c *client) IsBucketExist(ctx context.Context, bucketName string) (bool, error) {
	return c.BucketExists(ctx, bucketName)
}

func (c *client) GetDownloadLink(ctx context.Context, bucketName, fileName string, expire time.Duration) (string, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return "", err
	}

	signedUrl := fmt.Sprintf("https://%s:%s@webdav.eci.paracloud.com/%s/%s", volume.username, volume.password, bucketName, fileName)
	return signedUrl, nil
}

func (c *client) CreateDir(ctx context.Context, bucketName, folderName string) error {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return err
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	err = webdavClient.MkdirAll(filepath.Join(bucketName, folderName), types.DefaultFileMode)
	if err != nil {
		return err
	}

	return nil
}

func (c *client) GetDirMetadata(ctx context.Context, bucketName, folderKey string) (*FileInfo, bool, error) {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return nil, false, nil
	}

	webdavClient := gowebdav.NewClient(volume.url, volume.username, volume.password)
	stat, err := webdavClient.Stat(filepath.Join(bucketName, folderKey))
	if err != nil {
		return nil, false, err
	}

	if !stat.IsDir() || stat.Name() != filepath.Base(folderKey) {
		return nil, false, errors.New("noSuchKey")
	}

	return &FileInfo{
		Key:          folderKey,
		Size:         stat.Size(),
		LastModified: stat.ModTime(),
	}, true, nil
}

func (c *client) PostTransfer(ctx context.Context, bucketName, fileName string, isSuccess bool) error {
	volume, err := c.refreshVolumeCache(ctx)
	if err != nil {
		return err
	}

	err = c.removeClusterVolume(ctx, volume.clusterID, volume.accountID, volume.id)
	if err != nil {
		return err
	}

	volumeKey := c.redisStorage.MakeStorageKey([]string{c.urchinCacheHashKey}, types.StoragePrefixParaCloudVolume)
	err = c.redisStorage.Del(volumeKey)
	if err != nil {
		return err
	}

	return nil
}

// - init client
func initClient() (Client, error) {
	client, err := New("xxx", "yyy", "https://eci.paracloud.com/",
		"aaabbbcccdddeee", []string{"192.168.242.28:6379"}, "zzz", false)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func main() {

	ctx := context.Background()
	paraClient, _ := initClient()
	//
	//signedUrl, err := paraClient.GetDownloadLink(ctx, "urchincache", "jobs/node/attachments/mariadb_10.6.tar", 0, hashKey)
	//if err != nil {
	//	log.Printf("GetDownloadLink err:%v", err)
	//}
	//log.Printf("GetDownloadLink signedUrl:%v", signedUrl)

	//fd, _ := os.Open("/root/xxx/data/minio.out")
	//var readCloser io.ReadCloser = fd
	//err := paraClient.UploadFile(ctx, "urchincache", "jobs/node/attachments/test2.tar", "", readCloser)
	//if err != nil {
	//	log.Printf("UploadFile err:%v", err)
	//	return
	//}

	err := paraClient.PostTransfer(ctx, "urchincache", "jobs/node/attachments/test2.tar", true)
	if err != nil {
		log.Printf("PostTransfer err:%v", err)
		return
	}

	//exist, err := paraClient.StatFile(ctx, "urchincache", "jobs/node/attachments/test2.tar")
	//if err != nil {
	//	log.Printf("IsFileExist err:%v", err)
	//	//return
	//}
	//log.Printf("exist:%v", exist)

	log.Printf("ok...")
}
